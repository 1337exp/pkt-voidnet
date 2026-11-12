//! An established connection, the same on both ends (stage 3): authentication of DATA, the
//! receive window, acknowledgements, RTT, loss detection and probe timers, the three delivery
//! modes, keep-alive. Fixed memory, no allocation.
//!
//! Установленное соединение, одинаковое на обоих концах (этап 3): проверка DATA, окно приёма,
//! подтверждения, RTT, обнаружение потерь и таймеры проб, три режима доставки, keep-alive.
//! Фиксированная память, без выделения.

use crate::ack::{reconstruct_largest, AckFrame, ACK_DELAY_UNIT_US};
use crate::config::ChannelTable;
use crate::ring::Ring;
use crate::siphash::ct_eq_u64;
use crate::window::{Class, RecvWindow};
use crate::wire::{ChannelMode, DataDatagram, DataWriter, Frame, WriteError, MAX_CHANNELS};

// ---------------------------------------------------------------------------------------
// Build-time profile. Changing one of these is a different build of the library, not a
// run-time setting: the memory of a connection is known before it starts.
// Профиль сборки. Смена любого значения это другая сборка библиотеки, а не настройка
// времени работы: память соединения известна заранее.
// ---------------------------------------------------------------------------------------

/// Largest application message in bytes. / Наибольшее сообщение приложения.
pub const MSG_MAX: usize = 1200;
/// Reliable window in messages, per reliable channel and direction.
/// Окно надёжных сообщений на канал и направление.
pub const REL_WINDOW: usize = 16;
/// How many channels may be reliable. / Сколько каналов могут быть надёжными.
pub const MAX_RELIABLE_CHANNELS: usize = 2;
/// Unreliable messages waiting to be sent (oldest dropped when full).
/// Ненадёжные сообщения в очереди на отправку (при переполнении вытесняется старое).
pub const UQ_CAP: usize = 8;
/// Received messages waiting for the host. / Принятые сообщения в ожидании хозяина.
pub const DELIVER_CAP: usize = 8;
/// Packets tracked for acknowledgement and loss. / Отслеживаемые пакеты.
pub const SENT_CAP: usize = 64;
/// Reliable messages remembered per tracked packet. / Надёжных сообщений на пакет.
pub const MAX_REFS: usize = 8;

/// Packets a later acknowledgement must jump over to call an older one lost.
const PACKET_THRESHOLD: u64 = 3;
/// A sender must stay below this many unacknowledged packet numbers (wire.md, 2.1).
const MAX_RUNAHEAD: u64 = 1 << 14;
/// Probe timeout doubles at most this many times. / Предел удвоений таймаута пробы.
const MAX_PTO_BACKOFF: u32 = 6;

/// Per-connection timing settings. / Настройки времени соединения.
#[derive(Clone, Copy, Debug)]
pub struct ConnConfig {
    pub channels: ChannelTable,
    /// How long an acknowledgement may wait for company (a data datagram to ride on).
    pub max_ack_delay_us: u64,
    /// Send a PING after this long without sending anything. 0 disables keep-alive.
    pub keepalive_us: u64,
    /// RTT used before the first sample. / RTT до первого замера.
    pub initial_rtt_us: u64,
}

impl ConnConfig {
    /// `false` if the channel table needs more reliable channels than this build keeps state for.
    /// `false`, если в таблице больше надёжных каналов, чем рассчитано в этой сборке.
    pub fn is_supported(&self) -> bool {
        self.channels
            .as_slice()
            .iter()
            .filter(|m| **m == ChannelMode::ReliableOrdered)
            .count()
            <= MAX_RELIABLE_CHANNELS
    }
}

/// Why `send` did not accept a message. / Почему `send` не принял сообщение.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SendError {
    /// No such channel. / Нет такого канала.
    NoChannel,
    /// Longer than [`MSG_MAX`]. / Длиннее [`MSG_MAX`].
    TooBig,
    /// Reliable window full: the peer is not keeping up. Nothing was queued.
    /// Окно надёжных сообщений занято: пир не успевает. Ничего не поставлено в очередь.
    Full,
    /// The connection is not established. / Соединение не установлено.
    NotConnected,
}

/// Why a DATA datagram did not count. / Почему DATA не засчитана.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refused {
    BadToken,
    BadNumber,
    Duplicate,
    TooOld,
    /// A message is larger than [`MSG_MAX`] or a reliable message is outside the window. The
    /// whole datagram is dropped and not acknowledged, so an honest peer sends it again.
    Capacity,
}

/// What an accepted DATA datagram held that the connection layer above acts on.
/// Что было в принятой DATA, на что реагирует слой выше.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Accepted {
    pub ping: bool,
    pub disconnect: Option<u8>,
    pub ack_eliciting: bool,
}

/// One received message. / Одно принятое сообщение.
#[derive(Clone, Copy, Debug)]
pub struct Delivered {
    pub ch: u8,
    pub len: u16,
    pub data: [u8; MSG_MAX],
}

impl Default for Delivered {
    fn default() -> Self {
        Self {
            ch: 0,
            len: 0,
            data: [0; MSG_MAX],
        }
    }
}

impl Delivered {
    pub fn payload(&self) -> &[u8] {
        self.data.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// Counters of one connection. / Счётчики одного соединения.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnStats {
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub ack_only_sent: u64,
    pub packets_lost: u64,
    pub messages_resent: u64,
    pub duplicates_dropped: u64,
    pub refused_capacity: u64,
    pub stale_sequenced: u64,
    pub delivery_dropped: u64,
    pub unreliable_dropped: u64,
    pub probes: u64,
    /// Smoothed RTT, variation, smallest and latest sample; microseconds. 0 until measured.
    pub rtt_us: u64,
    pub rtt_var_us: u64,
    pub min_rtt_us: u64,
    pub latest_rtt_us: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
enum Slot {
    Free,
    /// Waiting to be (re)sent. / Ждёт (пере)отправки.
    Queued,
    InFlight,
    Acked,
}

#[derive(Clone, Copy)]
struct RelSlot {
    state: Slot,
    mseq: u16,
    len: u16,
    /// Sent at least once already, so another send is a repeat.
    sent_once: bool,
    data: [u8; MSG_MAX],
}

impl RelSlot {
    fn new() -> Self {
        Self {
            state: Slot::Free,
            mseq: 0,
            len: 0,
            sent_once: false,
            data: [0; MSG_MAX],
        }
    }
}

/// Send side of one reliable channel. / Отправляющая сторона надёжного канала.
struct RelTx {
    /// Oldest message not yet acknowledged. / Самое старое неподтверждённое.
    base: u16,
    /// Next message number to assign. / Следующий номер.
    next: u16,
    slots: [RelSlot; REL_WINDOW],
}

#[derive(Clone, Copy)]
struct RxSlot {
    used: bool,
    mseq: u16,
    len: u16,
    data: [u8; MSG_MAX],
}

/// Receive side of one reliable channel. / Принимающая сторона надёжного канала.
struct RelRx {
    /// Next message number to deliver. / Следующий номер к выдаче.
    next: u16,
    slots: [RxSlot; REL_WINDOW],
}

#[derive(Clone, Copy)]
struct UMsg {
    ch: u8,
    has_mseq: bool,
    mseq: u16,
    len: u16,
    data: [u8; MSG_MAX],
}

impl Default for UMsg {
    fn default() -> Self {
        Self {
            ch: 0,
            has_mseq: false,
            mseq: 0,
            len: 0,
            data: [0; MSG_MAX],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
enum Pkt {
    Pending,
    Acked,
    Lost,
}

#[derive(Clone, Copy)]
struct Sent {
    pn: u64,
    time_us: u64,
    eliciting: bool,
    state: Pkt,
    nrefs: u8,
    refs: [(u8, u16); MAX_REFS],
}

impl Sent {
    fn empty() -> Self {
        Self {
            pn: 0,
            time_us: 0,
            eliciting: false,
            state: Pkt::Acked,
            nrefs: 0,
            refs: [(0, 0); MAX_REFS],
        }
    }
}

/// Serial-number "a is newer than b" on 16 bits. / «a новее b» для 16-битных номеров.
fn newer(a: u16, b: u16) -> bool {
    a != b && a.wrapping_sub(b) < 0x8000
}

/// A connection. / Соединение.
pub struct Conn {
    cfg: ConnConfig,
    pub token: u64,
    win: RecvWindow,
    tx_pn: u64,
    pub last_recv_us: u64,
    last_send_us: u64,
    largest_recv_us: u64,

    // acknowledgements owed to the peer: they ride on the next datagram, or leave alone once
    // `max_ack_delay_us` has passed since `ack_since_us`
    ack_owed: bool,
    ack_since_us: u64,

    /// The host asked to send what is queued now. Cleared when nothing is queued any more.
    flush_pending: bool,

    // what the peer acknowledged of ours
    sent: [Sent; SENT_CAP],
    sent_head: usize,
    sent_len: usize,
    largest_acked: u64,
    has_largest: bool,

    // timing
    srtt_us: u64,
    rttvar_us: u64,
    min_rtt_us: u64,
    latest_rtt_us: u64,
    have_rtt: bool,
    pto_count: u32,
    probe: u8,
    ping_requested: bool,

    // channels
    rel_of: [u8; MAX_CHANNELS],
    rel_ch: [u8; MAX_RELIABLE_CHANNELS],
    rel_tx: [RelTx; MAX_RELIABLE_CHANNELS],
    rel_rx: [RelRx; MAX_RELIABLE_CHANNELS],
    seq_tx: [u16; MAX_CHANNELS],
    seq_rx: [u16; MAX_CHANNELS],
    seq_seen: [bool; MAX_CHANNELS],
    uq: Ring<UMsg, UQ_CAP>,
    delivery: Ring<Delivered, DELIVER_CAP>,
    stats: ConnStats,
}

impl Conn {
    pub fn new(token: u64, cfg: ConnConfig, now_us: u64) -> Self {
        let mut rel_of = [u8::MAX; MAX_CHANNELS];
        let mut rel_ch = [u8::MAX; MAX_RELIABLE_CHANNELS];
        let mut n = 0usize;
        for (i, m) in cfg.channels.as_slice().iter().enumerate() {
            if *m == ChannelMode::ReliableOrdered {
                if let (Some(r), Some(c)) = (rel_of.get_mut(i), rel_ch.get_mut(n)) {
                    *r = n as u8;
                    *c = i as u8;
                }
                n += 1;
            }
        }
        let mut c = Self {
            cfg,
            token: 0,
            win: RecvWindow::new(),
            tx_pn: 0,
            last_recv_us: now_us,
            last_send_us: now_us,
            largest_recv_us: now_us,
            ack_owed: false,
            ack_since_us: 0,
            flush_pending: false,
            sent: [Sent::empty(); SENT_CAP],
            sent_head: 0,
            sent_len: 0,
            largest_acked: 0,
            has_largest: false,
            srtt_us: cfg.initial_rtt_us,
            rttvar_us: cfg.initial_rtt_us / 2,
            min_rtt_us: 0,
            latest_rtt_us: 0,
            have_rtt: false,
            pto_count: 0,
            probe: 0,
            ping_requested: false,
            rel_of,
            rel_ch,
            rel_tx: core::array::from_fn(|_| RelTx {
                base: 0,
                next: 0,
                slots: [RelSlot::new(); REL_WINDOW],
            }),
            rel_rx: core::array::from_fn(|_| RelRx {
                next: 0,
                slots: [RxSlot {
                    used: false,
                    mseq: 0,
                    len: 0,
                    data: [0; MSG_MAX],
                }; REL_WINDOW],
            }),
            seq_tx: [0; MAX_CHANNELS],
            seq_rx: [0; MAX_CHANNELS],
            seq_seen: [false; MAX_CHANNELS],
            uq: Ring::new(),
            delivery: Ring::new(),
            stats: ConnStats::default(),
        };
        c.reset(token, cfg, now_us);
        c
    }

    /// Put the connection into the state [`new`](Self::new) builds, writing only the fields that
    /// carry state. The message buffers keep whatever bytes they hold: they are always written
    /// before they are read. This lets the host give the library zeroed memory of the right size
    /// and have the connection initialised in place, without building a 100 KB value on the stack.
    /// Привести соединение в состояние, которое строит `new`, записывая только поля состояния.
    /// Буферы сообщений остаются как были: их всегда пишут до чтения. Так хозяин может отдать
    /// обнулённую память и получить инициализацию на месте, без значения в 100 КБ на стеке.
    pub fn reset(&mut self, token: u64, cfg: ConnConfig, now_us: u64) {
        self.cfg = cfg;
        self.token = token;
        self.win = RecvWindow::new();
        self.tx_pn = 0;
        self.last_recv_us = now_us;
        self.last_send_us = now_us;
        self.largest_recv_us = now_us;
        self.ack_owed = false;
        self.ack_since_us = 0;
        self.flush_pending = false;
        for s in &mut self.sent {
            s.state = Pkt::Acked;
            s.nrefs = 0;
        }
        self.sent_head = 0;
        self.sent_len = 0;
        self.largest_acked = 0;
        self.has_largest = false;
        self.srtt_us = cfg.initial_rtt_us;
        self.rttvar_us = cfg.initial_rtt_us / 2;
        self.min_rtt_us = 0;
        self.latest_rtt_us = 0;
        self.have_rtt = false;
        self.pto_count = 0;
        self.probe = 0;
        self.ping_requested = false;
        self.rel_of = [u8::MAX; MAX_CHANNELS];
        self.rel_ch = [u8::MAX; MAX_RELIABLE_CHANNELS];
        let mut n = 0usize;
        for (i, m) in cfg.channels.as_slice().iter().enumerate() {
            if *m == ChannelMode::ReliableOrdered {
                if let (Some(r), Some(c)) = (self.rel_of.get_mut(i), self.rel_ch.get_mut(n)) {
                    *r = n as u8;
                    *c = i as u8;
                }
                n += 1;
            }
        }
        for tx in &mut self.rel_tx {
            tx.base = 0;
            tx.next = 0;
            for s in &mut tx.slots {
                s.state = Slot::Free;
                s.mseq = 0;
                s.len = 0;
                s.sent_once = false;
            }
        }
        for rx in &mut self.rel_rx {
            rx.next = 0;
            for s in &mut rx.slots {
                s.used = false;
                s.mseq = 0;
                s.len = 0;
            }
        }
        self.seq_tx = [0; MAX_CHANNELS];
        self.seq_rx = [0; MAX_CHANNELS];
        self.seq_seen = [false; MAX_CHANNELS];
        self.uq.reset();
        self.delivery.reset();
        self.stats = ConnStats::default();
    }

    pub fn stats(&self) -> ConnStats {
        ConnStats {
            rtt_us: if self.have_rtt { self.srtt_us } else { 0 },
            rtt_var_us: if self.have_rtt { self.rttvar_us } else { 0 },
            min_rtt_us: self.min_rtt_us,
            latest_rtt_us: self.latest_rtt_us,
            ..self.stats
        }
    }

    /// The next packet number to send; the wire carries its low 16 bits.
    pub fn next_pn(&mut self) -> u64 {
        let pn = self.tx_pn;
        self.tx_pn = self.tx_pn.wrapping_add(1);
        pn
    }

    fn largest(&self) -> Option<u64> {
        self.has_largest.then_some(self.largest_acked)
    }

    fn mode(&self, ch: u8) -> Option<ChannelMode> {
        self.cfg.channels.as_slice().get(usize::from(ch)).copied()
    }

    fn rel_index(&self, ch: u8) -> Option<usize> {
        let r = *self.rel_of.get(usize::from(ch))?;
        (r != u8::MAX).then_some(usize::from(r))
    }

    // ------------------------------------------------------------------------- sending

    /// Queue a message. Reliable messages either fit the window completely or are refused;
    /// unreliable ones replace the oldest waiting message when the queue is full. Nothing is sent
    /// by this call: the message leaves with the next datagram, which [`flush`](Self::flush) or a
    /// timer starts.
    /// Поставить сообщение в очередь. Надёжное либо входит в окно целиком, либо отклоняется;
    /// ненадёжное при переполнении вытесняет самое старое из ожидающих. Сама эта функция ничего
    /// не отправляет: сообщение уйдёт со следующей датаграммой, которую начнёт `flush` или таймер.
    pub fn send(&mut self, ch: u8, data: &[u8]) -> Result<(), SendError> {
        let mode = self.mode(ch).ok_or(SendError::NoChannel)?;
        if data.len() > MSG_MAX {
            return Err(SendError::TooBig);
        }
        let len = data.len() as u16;
        match mode {
            ChannelMode::ReliableOrdered => {
                let ri = self.rel_index(ch).ok_or(SendError::NoChannel)?;
                let tx = self.rel_tx.get_mut(ri).ok_or(SendError::NoChannel)?;
                if usize::from(tx.next.wrapping_sub(tx.base)) >= REL_WINDOW {
                    return Err(SendError::Full);
                }
                let mseq = tx.next;
                let slot = tx
                    .slots
                    .get_mut(usize::from(mseq) % REL_WINDOW)
                    .ok_or(SendError::Full)?;
                slot.state = Slot::Queued;
                slot.mseq = mseq;
                slot.len = len;
                slot.sent_once = false;
                if let Some(d) = slot.data.get_mut(..data.len()) {
                    d.copy_from_slice(data);
                }
                tx.next = tx.next.wrapping_add(1);
                Ok(())
            }
            ChannelMode::Unreliable | ChannelMode::UnreliableSequenced => {
                let mseq = if mode == ChannelMode::UnreliableSequenced {
                    let c = self
                        .seq_tx
                        .get_mut(usize::from(ch))
                        .ok_or(SendError::NoChannel)?;
                    let m = *c;
                    *c = c.wrapping_add(1);
                    Some(m)
                } else {
                    None
                };
                let mut m = UMsg {
                    ch,
                    has_mseq: mseq.is_some(),
                    mseq: mseq.unwrap_or(0),
                    len,
                    data: [0; MSG_MAX],
                };
                if let Some(d) = m.data.get_mut(..data.len()) {
                    d.copy_from_slice(data);
                }
                if self.uq.free() == 0 {
                    self.uq.pop();
                    self.stats.unreliable_dropped += 1;
                }
                self.uq.push(m);
                Ok(())
            }
        }
    }

    fn sent_at(&self, i: usize) -> Option<&Sent> {
        if i >= self.sent_len {
            return None;
        }
        self.sent.get((self.sent_head + i) % SENT_CAP)
    }

    fn sent_at_mut(&mut self, i: usize) -> Option<&mut Sent> {
        if i >= self.sent_len {
            return None;
        }
        self.sent.get_mut((self.sent_head + i) % SENT_CAP)
    }

    /// Requeue the reliable messages of a lost packet. / Вернуть в очередь надёжные
    /// сообщения потерянного пакета.
    fn requeue(&mut self, refs: [(u8, u16); MAX_REFS], n: u8) {
        for &(ch, mseq) in refs.iter().take(usize::from(n)) {
            let Some(ri) = self.rel_index(ch) else {
                continue;
            };
            let Some(tx) = self.rel_tx.get_mut(ri) else {
                continue;
            };
            if let Some(s) = tx.slots.get_mut(usize::from(mseq) % REL_WINDOW) {
                if s.mseq == mseq && s.state == Slot::InFlight {
                    s.state = Slot::Queued;
                }
            }
        }
    }

    fn pop_resolved(&mut self) {
        while self.sent_len > 0 {
            let done = self.sent_at(0).is_none_or(|s| s.state != Pkt::Pending);
            if !done {
                break;
            }
            self.sent_head = (self.sent_head + 1) % SENT_CAP;
            self.sent_len -= 1;
        }
    }

    fn ack_message(&mut self, ch: u8, mseq: u16) {
        let Some(ri) = self.rel_index(ch) else { return };
        let Some(tx) = self.rel_tx.get_mut(ri) else {
            return;
        };
        if let Some(s) = tx.slots.get_mut(usize::from(mseq) % REL_WINDOW) {
            if s.mseq == mseq && matches!(s.state, Slot::InFlight | Slot::Queued) {
                s.state = Slot::Acked;
            }
        }
        // free from the oldest forward
        while tx.base != tx.next {
            let Some(s) = tx.slots.get_mut(usize::from(tx.base) % REL_WINDOW) else {
                break;
            };
            if s.state == Slot::Acked {
                s.state = Slot::Free;
                tx.base = tx.base.wrapping_add(1);
            } else {
                break;
            }
        }
    }

    // ------------------------------------------------------------------------- timers

    fn pto_us(&self) -> u64 {
        let var = (self.rttvar_us * 4).max(1_000);
        self.srtt_us + var + self.cfg.max_ack_delay_us
    }

    fn loss_delay_us(&self) -> u64 {
        let base = self.srtt_us.max(self.latest_rtt_us);
        (base + base / 8).max(1_000)
    }

    /// The most recently sent packet that still waits for an acknowledgement. The probe timer
    /// runs from it, so each probe restarts the (backed-off) wait.
    /// Последний отправленный пакет, всё ещё ждущий подтверждения. Таймер пробы считается от
    /// него, поэтому каждая проба перезапускает (удлинённое) ожидание.
    fn newest_eliciting_pending(&self) -> Option<&Sent> {
        (0..self.sent_len)
            .rev()
            .filter_map(|i| self.sent_at(i))
            .find(|s| s.state == Pkt::Pending && s.eliciting)
    }

    /// When this connection next needs [`on_timeout`](Self::on_timeout) or a transmit.
    /// Когда соединению снова нужны `on_timeout` или отправка.
    pub fn next_deadline(&self) -> Option<u64> {
        let mut t = u64::MAX;
        if self.flush_pending && self.has_queued() || self.has_retransmit() {
            t = 0;
        }
        if self.ack_owed {
            t = t.min(self.ack_since_us.saturating_add(self.cfg.max_ack_delay_us));
        }
        if let Some(p) = self.newest_eliciting_pending() {
            let backoff = self.pto_count.min(MAX_PTO_BACKOFF);
            t = t.min(p.time_us.saturating_add(self.pto_us() << backoff));
        }
        // a pending packet older than the largest acknowledged one is lost by time
        if let Some(la) = self.largest() {
            let ld = self.loss_delay_us();
            for s in (0..self.sent_len).filter_map(|i| self.sent_at(i)) {
                if s.state == Pkt::Pending && s.pn < la {
                    t = t.min(s.time_us.saturating_add(ld));
                }
            }
        }
        if self.cfg.keepalive_us > 0 {
            t = t.min(self.last_send_us.saturating_add(self.cfg.keepalive_us));
        }
        (t != u64::MAX).then_some(t)
    }

    /// Run the timers that are due: time-based loss, then the probe timeout.
    /// Выполнить сработавшие таймеры: потери по времени, затем таймаут пробы.
    pub fn on_timeout(&mut self, now_us: u64) {
        self.detect_loss(now_us);
        if let Some(p) = self.newest_eliciting_pending() {
            let backoff = self.pto_count.min(MAX_PTO_BACKOFF);
            if now_us >= p.time_us.saturating_add(self.pto_us() << backoff) {
                self.pto_count = self.pto_count.saturating_add(1);
                self.probe = 2;
                self.stats.probes += 1;
            }
        }
    }

    fn update_rtt(&mut self, sample_us: u64) {
        self.latest_rtt_us = sample_us;
        if !self.have_rtt {
            self.have_rtt = true;
            self.srtt_us = sample_us;
            self.rttvar_us = sample_us / 2;
            self.min_rtt_us = sample_us;
            return;
        }
        self.min_rtt_us = self.min_rtt_us.min(sample_us);
        let d = self.srtt_us.abs_diff(sample_us);
        self.rttvar_us = (3 * self.rttvar_us + d) / 4;
        self.srtt_us = (7 * self.srtt_us + sample_us) / 8;
    }

    fn detect_loss(&mut self, now_us: u64) {
        let Some(la) = self.largest() else { return };
        let ld = self.loss_delay_us();
        for i in 0..self.sent_len {
            let Some(s) = self.sent_at(i) else { break };
            if s.state != Pkt::Pending || s.pn >= la {
                continue;
            }
            let lost = la - s.pn >= PACKET_THRESHOLD || now_us.saturating_sub(s.time_us) >= ld;
            if lost {
                let (refs, n) = (s.refs, s.nrefs);
                if let Some(s) = self.sent_at_mut(i) {
                    s.state = Pkt::Lost;
                }
                self.stats.packets_lost += 1;
                self.requeue(refs, n);
            }
        }
        self.pop_resolved();
    }

    fn on_ack(&mut self, a: &AckFrame, now_us: u64) {
        let Some(highest_sent) = self.tx_pn.checked_sub(1) else {
            return;
        };
        let Some(largest) = reconstruct_largest(highest_sent, a.largest) else {
            return;
        };
        let Some(ranges) = a.ranges(largest) else {
            return;
        };
        self.largest_acked = if self.has_largest {
            self.largest_acked.max(largest)
        } else {
            largest
        };
        self.has_largest = true;
        let mut ranges_buf = [(0u64, 0u64); 16];
        let mut nr = 0;
        for r in ranges {
            if let Some(slot) = ranges_buf.get_mut(nr) {
                *slot = r;
                nr += 1;
            }
        }
        let covered = |pn: u64| {
            ranges_buf
                .iter()
                .take(nr)
                .any(|&(lo, hi)| pn >= lo && pn <= hi)
        };
        let mut newly_eliciting = false;
        for i in 0..self.sent_len {
            let Some(s) = self.sent_at(i) else { break };
            if s.state != Pkt::Pending || !covered(s.pn) {
                continue;
            }
            let (pn, time, eliciting, refs, n) = (s.pn, s.time_us, s.eliciting, s.refs, s.nrefs);
            if let Some(s) = self.sent_at_mut(i) {
                s.state = Pkt::Acked;
            }
            for &(ch, mseq) in refs.iter().take(usize::from(n)) {
                self.ack_message(ch, mseq);
            }
            newly_eliciting |= eliciting;
            if pn == largest && eliciting {
                let delay = u64::from(a.delay)
                    .saturating_mul(ACK_DELAY_UNIT_US)
                    .min(self.cfg.max_ack_delay_us);
                let sample = now_us.saturating_sub(time).saturating_sub(delay).max(1);
                self.update_rtt(sample);
            }
        }
        if newly_eliciting {
            self.pto_count = 0;
        }
        self.detect_loss(now_us);
        self.pop_resolved();
        self.settle_flush();
    }

    // ------------------------------------------------------------------------- receiving

    /// Check a DATA datagram and, only if it is authentic, new and acceptable, apply it. A
    /// failed check changes nothing (invariant I6).
    /// Проверить DATA и только для подлинной, новой и приемлемой применить её. Неудачная
    /// проверка ничего не меняет (инвариант I6).
    pub fn on_datagram(&mut self, dd: &DataDatagram<'_>, now_us: u64) -> Result<Accepted, Refused> {
        if !ct_eq_u64(dd.token, self.token) {
            return Err(Refused::BadToken);
        }
        let pn = self.win.reconstruct(dd.pn).ok_or(Refused::BadNumber)?;
        match self.win.classify(pn) {
            Class::Duplicate => {
                self.stats.duplicates_dropped += 1;
                return Err(Refused::Duplicate);
            }
            Class::TooOld => return Err(Refused::TooOld),
            Class::New => {}
        }
        // dry run: refuse the whole datagram, unacknowledged, if a message cannot be kept
        for f in dd.frames() {
            if let Frame::Msg { ch, mseq, payload } = f {
                if payload.len() > MSG_MAX {
                    self.stats.refused_capacity += 1;
                    return Err(Refused::Capacity);
                }
                if let (Some(ri), Some(m)) = (self.rel_index(ch), mseq) {
                    let next = self.rel_rx.get(ri).map_or(0, |r| r.next);
                    let d = m.wrapping_sub(next);
                    if usize::from(d) >= REL_WINDOW && d < 0x8000 {
                        self.stats.refused_capacity += 1;
                        return Err(Refused::Capacity);
                    }
                }
            }
        }
        self.win.mark(pn);
        self.stats.packets_recv += 1;
        self.stats.bytes_recv += dd.wire_len() as u64;
        self.last_recv_us = self.last_recv_us.max(now_us);
        if self.win.largest() == Some(pn) {
            self.largest_recv_us = now_us;
        }
        let mut out = Accepted {
            ping: false,
            disconnect: None,
            ack_eliciting: false,
        };
        for f in dd.frames() {
            out.ack_eliciting |= f.ack_eliciting();
            match f {
                Frame::Ack(a) => self.on_ack(&a, now_us),
                Frame::Msg { ch, mseq, payload } => self.on_message(ch, mseq, payload),
                Frame::Ping => out.ping = true,
                Frame::Disconnect { reason } => out.disconnect = Some(reason),
            }
        }
        // The acknowledgement waits for a datagram to ride on; the clock starts with the oldest
        // packet that is not acknowledged yet.
        if out.ack_eliciting && !self.ack_owed {
            self.ack_owed = true;
            self.ack_since_us = now_us;
        }
        self.drain_reorder();
        Ok(out)
    }

    fn deliver(&mut self, ch: u8, data: &[u8]) {
        let mut d = Delivered {
            ch,
            len: data.len() as u16,
            data: [0; MSG_MAX],
        };
        if let Some(dst) = d.data.get_mut(..data.len()) {
            dst.copy_from_slice(data);
        }
        if !self.delivery.push(d) {
            self.stats.delivery_dropped += 1;
        }
    }

    fn on_message(&mut self, ch: u8, mseq: Option<u16>, payload: &[u8]) {
        match self.mode(ch) {
            Some(ChannelMode::Unreliable) => self.deliver(ch, payload),
            Some(ChannelMode::UnreliableSequenced) => {
                let Some(m) = mseq else { return };
                let i = usize::from(ch);
                let fresh = !self.seq_seen.get(i).copied().unwrap_or(false)
                    || newer(m, self.seq_rx.get(i).copied().unwrap_or(0));
                if fresh {
                    if let (Some(a), Some(b)) = (self.seq_rx.get_mut(i), self.seq_seen.get_mut(i)) {
                        *a = m;
                        *b = true;
                    }
                    self.deliver(ch, payload);
                } else {
                    self.stats.stale_sequenced += 1;
                }
            }
            Some(ChannelMode::ReliableOrdered) => {
                let (Some(ri), Some(m)) = (self.rel_index(ch), mseq) else {
                    return;
                };
                let Some(rx) = self.rel_rx.get_mut(ri) else {
                    return;
                };
                let d = m.wrapping_sub(rx.next);
                if d >= 0x8000 {
                    return; // already delivered earlier: a duplicate
                }
                if let Some(s) = rx.slots.get_mut(usize::from(m) % REL_WINDOW) {
                    if !s.used {
                        s.used = true;
                        s.mseq = m;
                        s.len = payload.len() as u16;
                        if let Some(dst) = s.data.get_mut(..payload.len()) {
                            dst.copy_from_slice(payload);
                        }
                    }
                }
            }
            None => {}
        }
    }

    /// Move in-order reliable messages to the delivery queue while there is room.
    /// Переложить надёжные сообщения по порядку в очередь выдачи, пока есть место.
    fn drain_reorder(&mut self) {
        for ri in 0..MAX_RELIABLE_CHANNELS {
            let ch = self.rel_ch.get(ri).copied().unwrap_or(u8::MAX);
            if ch == u8::MAX {
                continue;
            }
            loop {
                if self.delivery.free() == 0 {
                    return;
                }
                let Some(rx) = self.rel_rx.get_mut(ri) else {
                    break;
                };
                let idx = usize::from(rx.next) % REL_WINDOW;
                let next = rx.next;
                let Some(s) = rx.slots.get_mut(idx) else {
                    break;
                };
                if !(s.used && s.mseq == next) {
                    break;
                }
                let mut d = Delivered {
                    ch,
                    len: s.len,
                    data: [0; MSG_MAX],
                };
                d.data = s.data;
                s.used = false;
                rx.next = rx.next.wrapping_add(1);
                self.delivery.push(d);
            }
        }
    }

    /// The oldest received message, if any. / Самое старое принятое сообщение.
    pub fn poll_recv(&mut self) -> Option<Delivered> {
        let d = self.delivery.pop();
        self.drain_reorder();
        d
    }

    pub fn has_delivery(&self) -> bool {
        !self.delivery.is_empty()
    }

    // ------------------------------------------------------------------------- transmit

    /// Ask for a PING in the next datagram (used by the client to confirm the connection).
    /// Попросить PING в ближайшей датаграмме (клиент так подтверждает соединение).
    pub fn queue_ping(&mut self) {
        self.ping_requested = true;
    }

    fn has_queued_reliable(&self) -> bool {
        self.rel_tx
            .iter()
            .any(|tx| tx.slots.iter().any(|s| s.state == Slot::Queued))
    }

    /// A reliable message that was sent before and is waiting to go again (its packet was lost).
    /// Надёжное сообщение, которое уже уходило и ждёт повтора (его пакет потерян).
    fn has_retransmit(&self) -> bool {
        self.rel_tx.iter().any(|tx| {
            tx.slots
                .iter()
                .any(|s| s.state == Slot::Queued && s.sent_once)
        })
    }

    /// Anything waiting for a datagram. / Есть ли что-то, ждущее датаграммы.
    fn has_queued(&self) -> bool {
        self.has_queued_reliable() || !self.uq.is_empty()
    }

    /// A flush covers what is queued; once nothing is, it is spent. Without this a flush left
    /// over after the queue emptied (a repeat acknowledged in the meantime) would send the next
    /// message the host queues without being asked.
    /// Flush относится к тому, что в очереди; когда очередь пуста, он исчерпан.
    fn settle_flush(&mut self) {
        if !self.has_queued() {
            self.flush_pending = false;
        }
    }

    /// Send what is queued now: the next [`build`](Self::build) produces a datagram for it.
    /// Does nothing when nothing is queued (it never makes an acknowledgement-only datagram).
    /// Отправить то, что в очереди: ближайший `build` соберёт для этого датаграмму. Если очередь
    /// пуста, не делает ничего (датаграмму из одного подтверждения он не порождает).
    pub fn flush(&mut self) {
        self.flush_pending = self.has_queued();
    }

    fn ack_due(&self, now_us: u64) -> bool {
        self.ack_owed && now_us >= self.ack_since_us.saturating_add(self.cfg.max_ack_delay_us)
    }

    fn ping_due(&self, now_us: u64) -> bool {
        self.cfg.keepalive_us > 0
            && now_us.saturating_sub(self.last_send_us) >= self.cfg.keepalive_us
    }

    /// Whether [`build`](Self::build) starts a datagram now: a flush with something queued, an
    /// acknowledgement that has waited `max_ack_delay`, a message to repeat, a probe, a PING.
    /// Messages queued without a flush do not count; they ride with such a datagram.
    /// Начнёт ли `build` датаграмму сейчас: flush при непустой очереди, подтверждение,
    /// прождавшее `max_ack_delay`, повтор, проба, PING. Сообщения без flush не в счёт: они едут
    /// с такой датаграммой.
    pub fn wants_to_send(&self, now_us: u64) -> bool {
        (self.flush_pending && self.has_queued())
            || self.ack_due(now_us)
            || self.has_retransmit()
            || self.probe > 0
            || self.ping_requested
            || self.ping_due(now_us)
    }

    /// Build the next DATA datagram for this connection into `buf`, or `None`.
    /// Собрать следующую DATA этого соединения в `buf` или `None`.
    pub fn build(&mut self, now_us: u64, buf: &mut [u8]) -> Option<usize> {
        let n = self.build_datagram(now_us, buf);
        self.settle_flush();
        n
    }

    fn build_datagram(&mut self, now_us: u64, buf: &mut [u8]) -> Option<usize> {
        if !self.wants_to_send(now_us) {
            return None;
        }
        // never run 2^15 packet numbers ahead of what the peer has confirmed
        if self.tx_pn.saturating_sub(self.largest_acked) >= MAX_RUNAHEAD {
            return None;
        }
        let channels = self.cfg.channels;
        let pn = self.tx_pn;
        let mut w = DataWriter::new(buf, channels.as_slice(), self.token, pn as u16).ok()?;

        let mut acked_now = false;
        if self.ack_owed {
            let delay = (now_us.saturating_sub(self.largest_recv_us) / ACK_DELAY_UNIT_US) as u32;
            if let Some(frame) = AckFrame::from_window(&self.win, delay) {
                acked_now = w.ack(&frame).is_ok();
            }
        }

        let mut refs = [(0u8, 0u16); MAX_REFS];
        let mut nrefs = 0usize;
        let mut messages = 0usize;
        let mut resent = 0u64;

        'rel: for ri in 0..MAX_RELIABLE_CHANNELS {
            let ch = self.rel_ch.get(ri).copied().unwrap_or(u8::MAX);
            if ch == u8::MAX {
                continue;
            }
            let Some(tx) = self.rel_tx.get_mut(ri) else {
                continue;
            };
            let mut m = tx.base;
            while m != tx.next {
                if nrefs >= MAX_REFS {
                    break 'rel;
                }
                let idx = usize::from(m) % REL_WINDOW;
                if let Some(s) = tx.slots.get_mut(idx) {
                    let force_probe = self.probe > 0 && s.state == Slot::InFlight && m == tx.base;
                    if s.state == Slot::Queued || force_probe {
                        let payload = s.data.get(..usize::from(s.len)).unwrap_or(&[]);
                        match w.msg(ch, Some(m), payload) {
                            Ok(()) => {
                                if let Some(r) = refs.get_mut(nrefs) {
                                    *r = (ch, m);
                                    nrefs += 1;
                                }
                                if s.sent_once {
                                    resent += 1;
                                }
                                s.sent_once = true;
                                s.state = Slot::InFlight;
                                messages += 1;
                            }
                            Err(WriteError::NoSpace) => break 'rel,
                            Err(_) => break 'rel,
                        }
                    }
                }
                m = m.wrapping_add(1);
            }
        }

        while let Some(u) = self.uq.peek() {
            let payload = u.data.get(..usize::from(u.len)).unwrap_or(&[]);
            if w.msg(u.ch, u.has_mseq.then_some(u.mseq), payload).is_err() {
                break;
            }
            messages += 1;
            self.uq.pop();
        }

        let mut ping = false;
        if messages == 0 && (self.probe > 0 || self.ping_requested || self.ping_due(now_us)) {
            ping = w.ping().is_ok();
            if ping {
                self.ping_requested = false;
            }
        }
        let eliciting = messages > 0 || ping;
        if !acked_now && !eliciting {
            return None;
        }
        let n = w.finish().ok()?;

        // book-keeping, only now that the datagram exists
        if acked_now {
            self.ack_owed = false;
        }
        if self.probe > 0 && eliciting {
            self.probe -= 1;
        }
        self.stats.messages_resent += resent;
        self.stats.packets_sent += 1;
        self.stats.bytes_sent += n as u64;
        if !eliciting {
            self.stats.ack_only_sent += 1;
        }
        self.last_send_us = now_us;
        self.tx_pn = self.tx_pn.wrapping_add(1);

        // remember it (an old unresolved packet makes room and counts as lost)
        if self.sent_len == SENT_CAP {
            let (r, k) = self
                .sent_at(0)
                .map_or(([(0, 0); MAX_REFS], 0), |s| (s.refs, s.nrefs));
            let was_pending = self.sent_at(0).is_some_and(|s| s.state == Pkt::Pending);
            if was_pending {
                self.stats.packets_lost += 1;
                self.requeue(r, k);
            }
            self.sent_head = (self.sent_head + 1) % SENT_CAP;
            self.sent_len -= 1;
        }
        let tail = (self.sent_head + self.sent_len) % SENT_CAP;
        if let Some(slot) = self.sent.get_mut(tail) {
            *slot = Sent {
                pn,
                time_us: now_us,
                eliciting,
                state: if eliciting { Pkt::Pending } else { Pkt::Acked },
                nrefs: nrefs as u8,
                refs,
            };
            self.sent_len += 1;
        }
        self.pop_resolved();
        Some(n)
    }
}
