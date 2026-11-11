//! Server side of the handshake and the connection table (stage 2).
//!
//! No state exists before a valid cookie. A connection occupies a slot from a valid
//! RESPONSE, is announced to the host (`Event::Connected`) only when the client's first
//! authentic DATA arrives, and is dropped when it goes silent. Everything here has a fixed
//! upper bound: slots, rate table, reply queue, event queue.
//!
//! Серверная сторона рукопожатия и таблица соединений (этап 2). До верной куки состояния
//! нет. Соединение занимает слот с верного RESPONSE, объявляется хозяину (`Event::Connected`)
//! только с первой подлинной DATA клиента и снимается при молчании. У всего есть верхняя
//! граница: слоты, таблица лимитов, очередь ответов, очередь событий.

use crate::addr::Addr;
use crate::config::{ConfigError, ServerConfig};
use crate::conn::{Conn, ConnStats, Refused, SendError, MSG_MAX};
use crate::limit::{Bucket, RateTable};
use crate::ring::Ring;
use crate::siphash::{ct_eq_u64, siphash13};
use crate::wire::{
    self, reject_code, DataWriter, Datagram, HelloFields, WriteError, MAX_DATAGRAM, WIRE_VERSION,
};

/// Queued replies waiting for `poll_transmit`. / Ответы в очереди на отправку.
pub const REPLY_CAP: usize = 64;
const TAG_COOKIE: u8 = 0x01;
const TAG_TOKEN: u8 = 0x02;

/// Handle of a connection: slot index and a generation that changes when the slot is
/// reused, so a stale handle never reaches a new connection.
/// Дескриптор соединения: индекс слота и поколение, меняющееся при повторном занятии слота.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ConnId {
    pub index: u32,
    pub generation: u32,
}

/// Why a connection ended. / Почему соединение закончилось.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Closed {
    /// The host closed it, with this reason code.
    Local(u8),
    /// The peer sent DISCONNECT with this reason code.
    Remote(u8),
    /// No valid datagram for the idle timeout.
    Timeout,
    /// The same address connected again with a new `client_random`.
    Replaced,
}

/// What the host learns. Events are never overwritten or dropped.
/// Что узнаёт хозяин. События не затираются и не теряются.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Event {
    Connected { conn: ConnId, addr: Addr },
    Disconnected { conn: ConnId, reason: Closed },
}

impl Default for Event {
    fn default() -> Self {
        Event::Disconnected {
            conn: ConnId::default(),
            reason: Closed::Timeout,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum Body {
    Challenge { coarse: u32, cookie: u64 },
    Accept { token: u64, echo: u64 },
    Reject { code: u8, echo: u64 },
    Disconnect { token: u64, pn: u64, reason: u8 },
}

#[derive(Clone, Copy, Debug)]
struct Reply {
    to: Addr,
    body: Body,
}

impl Default for Reply {
    fn default() -> Self {
        Self {
            to: Addr::default(),
            body: Body::Reject { code: 0, echo: 0 },
        }
    }
}

/// Counters of what the server saw and did. / Счётчики того, что видел и делал сервер.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerStats {
    pub datagrams: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub parse_errors: u64,
    pub hello: u64,
    pub response: u64,
    pub data: u64,
    pub other_kinds: u64,
    pub rate_limited_source: u64,
    pub rate_limited_global: u64,
    pub bad_cookie: u64,
    pub stale_cookie: u64,
    pub challenges: u64,
    pub accepted: u64,
    pub reaccepted: u64,
    pub rejected_version: u64,
    pub rejected_config: u64,
    pub rejected_full: u64,
    pub rejected_source: u64,
    pub deferred_pending: u64,
    pub replaced: u64,
    pub confirmed: u64,
    pub unknown_peer: u64,
    pub bad_token: u64,
    pub dropped_replay: u64,
    pub refused_capacity: u64,
    pub unconfirmed_expired: u64,
    pub idle_expired: u64,
    pub replies_dropped: u64,
    pub events_lost: u64,
}

struct Slot {
    used: bool,
    confirmed: bool,
    generation: u32,
    addr: Addr,
    addr_hash: u64,
    client_random: u64,
    created_us: u64,
    conn: Conn,
}

impl Slot {
    fn empty(cfg: &ServerConfig) -> Self {
        Self {
            used: false,
            confirmed: false,
            generation: 0,
            addr: Addr::default(),
            addr_hash: 0,
            client_random: 0,
            created_us: 0,
            conn: Conn::new(0, cfg.conn_config(), 0),
        }
    }
}

/// A message received from a connection, see [`Server::poll_recv`].
/// Принятое сообщение, см. [`Server::poll_recv`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Received {
    pub conn: ConnId,
    pub ch: u8,
    pub len: usize,
}

/// The server: `N` connection slots, `R` rate-limit entries, `E` event slots (`E >= 2N + 2`).
/// Сервер: `N` слотов соединений, `R` записей лимитера, `E` мест под события (`E >= 2N + 2`).
pub struct Server<const N: usize, const R: usize, const E: usize> {
    cfg: ServerConfig,
    secret: [u8; 16],
    prev_secret: [u8; 16],
    has_prev: bool,
    token_key: [u8; 16],
    hash_key: [u8; 16],
    next_rotation_us: u64,
    conn_counter: u64,
    rr: usize,
    limiter: RateTable<R>,
    global: Bucket,
    slots: [Slot; N],
    used: usize,
    replies: Ring<Reply, REPLY_CAP>,
    events: Ring<Event, E>,
    stats: ServerStats,
}

fn secs(now_us: u64) -> u32 {
    (now_us / 1_000_000) as u32
}

impl<const N: usize, const R: usize, const E: usize> Server<N, R, E> {
    /// `seed` must be 32 fresh random bytes from the host; the core has no randomness.
    /// `seed`: 32 случайных байта от хозяина; у ядра своей случайности нет.
    pub fn new(cfg: ServerConfig, seed: [u8; 32], now_us: u64) -> Result<Self, ConfigError> {
        const { assert!(E >= 2 * N + 2, "event queue must hold two events per slot") };
        cfg.validate()?;
        let (a, b) = seed.split_at(16);
        let mut secret = [0u8; 16];
        let mut token_key = [0u8; 16];
        secret.copy_from_slice(a);
        token_key.copy_from_slice(b);
        let mut hash_key = [0u8; 16];
        let h0 = siphash13(&token_key, b"voidnet addr hash 0");
        let h1 = siphash13(&secret, b"voidnet addr hash 1");
        hash_key[..8].copy_from_slice(&h0.to_le_bytes());
        hash_key[8..].copy_from_slice(&h1.to_le_bytes());
        Ok(Self {
            cfg,
            secret,
            prev_secret: secret,
            has_prev: false,
            token_key,
            hash_key,
            next_rotation_us: now_us.saturating_add(cfg.rotation_interval_us),
            conn_counter: 0,
            rr: 0,
            limiter: RateTable::new(),
            global: Bucket::default(),
            slots: core::array::from_fn(|_| Slot::empty(&cfg)),
            used: 0,
            replies: Ring::new(),
            events: Ring::new(),
            stats: ServerStats::default(),
        })
    }

    /// Put the server into the state [`new`](Self::new) builds, in place: only the fields that
    /// carry state are written, so the host can give zeroed memory and no large value is built on
    /// the stack. On an error nothing is changed.
    /// Привести сервер в состояние `new` на месте: пишутся только поля состояния, поэтому хозяин
    /// может отдать обнулённую память, а большое значение на стеке не строится.
    pub fn reset(
        &mut self,
        cfg: ServerConfig,
        seed: [u8; 32],
        now_us: u64,
    ) -> Result<(), ConfigError> {
        cfg.validate()?;
        let (a, b) = seed.split_at(16);
        self.secret.copy_from_slice(a);
        self.prev_secret.copy_from_slice(a);
        self.token_key.copy_from_slice(b);
        let h0 = siphash13(&self.token_key, b"voidnet addr hash 0");
        let h1 = siphash13(&self.secret, b"voidnet addr hash 1");
        self.hash_key[..8].copy_from_slice(&h0.to_le_bytes());
        self.hash_key[8..].copy_from_slice(&h1.to_le_bytes());
        self.cfg = cfg;
        self.has_prev = false;
        self.next_rotation_us = now_us.saturating_add(cfg.rotation_interval_us);
        self.conn_counter = 0;
        self.rr = 0;
        self.limiter.reset();
        self.global = Bucket::default();
        let conn_cfg = cfg.conn_config();
        for s in &mut self.slots {
            s.used = false;
            s.confirmed = false;
            s.generation = 0;
            s.addr = Addr::default();
            s.addr_hash = 0;
            s.client_random = 0;
            s.created_us = 0;
            s.conn.reset(0, conn_cfg, 0);
        }
        self.used = 0;
        self.replies.reset();
        self.events.reset();
        self.stats = ServerStats::default();
        Ok(())
    }

    pub fn stats(&self) -> &ServerStats {
        &self.stats
    }

    pub fn slots_in_use(&self) -> usize {
        self.used
    }

    /// Replies waiting to be sent. / Ответов в очереди.
    pub fn pending_replies(&self) -> usize {
        self.replies.len()
    }

    /// Host call: replace the cookie secret with 16 fresh random bytes. The previous one
    /// stays valid for one more period. / Заменить секрет куки; предыдущий ещё действует.
    pub fn rotate_secret(&mut self, fresh: [u8; 16], now_us: u64) {
        self.prev_secret = self.secret;
        self.has_prev = true;
        self.secret = fresh;
        self.next_rotation_us = now_us.saturating_add(self.cfg.rotation_interval_us);
    }

    /// When the host should call [`handle_timeout`](Self::handle_timeout) or
    /// [`rotate_secret`](Self::rotate_secret) next. / Когда хозяину звать в следующий раз.
    pub fn next_deadline(&self) -> Option<u64> {
        let mut t = self.next_rotation_us;
        for s in self.slots.iter().filter(|s| s.used) {
            t = t.min(self.expiry(s));
            if let Some(d) = s.conn.next_deadline() {
                t = t.min(d);
            }
        }
        (t != u64::MAX).then_some(t)
    }

    /// When a slot is dropped for silence. / Когда слот снимается за молчание.
    fn expiry(&self, s: &Slot) -> u64 {
        if s.confirmed {
            s.conn.last_recv_us.saturating_add(self.cfg.idle_timeout_us)
        } else {
            s.created_us.saturating_add(self.cfg.unconfirmed_timeout_us)
        }
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop()
    }

    pub fn conn_addr(&self, conn: ConnId) -> Option<Addr> {
        let s = self.slot_of(conn)?;
        s.confirmed.then_some(s.addr)
    }

    fn slot_of(&self, conn: ConnId) -> Option<&Slot> {
        let s = self.slots.get(conn.index as usize)?;
        (s.used && s.generation == conn.generation).then_some(s)
    }

    fn max_slots(&self) -> usize {
        self.cfg.max_connections.min(N)
    }

    fn addr_hash(&self, a: &Addr) -> u64 {
        siphash13(&self.hash_key, a.as_bytes())
    }

    fn find(&self, a: &Addr) -> Option<usize> {
        let h = self.addr_hash(a);
        self.slots
            .iter()
            .position(|s| s.used && s.addr_hash == h && s.addr == *a)
    }

    /// `(all, pending)` connections that share the source of `a`.
    fn same_source(&self, a: &Addr) -> (usize, usize) {
        let mut all = 0;
        let mut pending = 0;
        for s in &self.slots {
            if s.used && s.addr.source() == a.source() {
                all += 1;
                pending += usize::from(!s.confirmed);
            }
        }
        (all, pending)
    }

    fn cookie_for(&self, secret: &[u8; 16], a: &Addr, coarse: u32, h: &HelloFields) -> u64 {
        let mut msg = [0u8; 2 + crate::addr::ADDR_MAX + 4 + wire::HELLO_FIELDS_LEN];
        let mut n = 0usize;
        let mut put = |bytes: &[u8]| {
            if let Some(d) = msg.get_mut(n..n + bytes.len()) {
                d.copy_from_slice(bytes);
                n += bytes.len();
            }
        };
        put(&[TAG_COOKIE, a.as_bytes().len() as u8]);
        put(a.as_bytes());
        put(&coarse.to_le_bytes());
        put(&h.to_bytes());
        siphash13(secret, msg.get(..n).unwrap_or(&[]))
    }

    fn make_token(&mut self, a: &Addr, client_random: u64) -> u64 {
        let mut msg = [0u8; 2 + crate::addr::ADDR_MAX + 16];
        let mut n = 0usize;
        let mut put = |bytes: &[u8]| {
            if let Some(d) = msg.get_mut(n..n + bytes.len()) {
                d.copy_from_slice(bytes);
                n += bytes.len();
            }
        };
        put(&[TAG_TOKEN, a.as_bytes().len() as u8]);
        put(a.as_bytes());
        put(&client_random.to_le_bytes());
        put(&self.conn_counter.to_le_bytes());
        self.conn_counter = self.conn_counter.wrapping_add(1);
        siphash13(&self.token_key, msg.get(..n).unwrap_or(&[]))
    }

    fn reply(&mut self, to: Addr, body: Body) {
        if !self.replies.push(Reply { to, body }) {
            self.stats.replies_dropped += 1;
        }
    }

    /// `Some(code)` when the client's fields are not acceptable. / Код отказа или `None`.
    fn check_fields(&self, h: &HelloFields) -> Option<u8> {
        if h.wire_version != WIRE_VERSION
            || h.protocol_id != self.cfg.protocol_id
            || (self.cfg.app_version != 0 && h.app_version != self.cfg.app_version)
        {
            return Some(reject_code::VERSION);
        }
        if h.config_hash != self.cfg.config_hash() {
            return Some(reject_code::CONFIG);
        }
        None
    }

    /// Whether the event queue can take everything the existing slots plus one more may
    /// still produce, so that events are never lost. / Хватит ли очереди событий на всё,
    /// что могут породить текущие слоты и ещё один.
    fn event_room(&self) -> bool {
        self.events.free() >= 2 * (self.used + 1)
    }

    /// Feed one datagram from `from`. Never panics, never allocates; replies are queued and
    /// leave through [`poll_transmit`](Self::poll_transmit).
    /// Принять датаграмму. Не паникует, не выделяет память; ответы встают в очередь.
    pub fn handle_datagram(&mut self, from: &Addr, data: &[u8], now_us: u64) {
        self.stats.datagrams += 1;
        self.stats.bytes_in += data.len() as u64;
        let channels = self.cfg.channels;
        let Ok(d) = wire::parse(data, channels.as_slice()) else {
            self.stats.parse_errors += 1;
            return;
        };
        match d {
            Datagram::Hello(h) => self.on_hello(from, &h, now_us),
            Datagram::Response {
                coarse,
                cookie,
                hello,
            } => self.on_response(from, coarse, cookie, &hello, now_us),
            Datagram::Data(dd) => self.on_data(from, &dd, now_us),
            _ => self.stats.other_kinds += 1,
        }
    }

    fn on_hello(&mut self, from: &Addr, h: &HelloFields, now_us: u64) {
        self.stats.hello += 1;
        // The per-source bucket goes first: a flood from one address then spends only its own
        // tokens and a few global ones, not the whole global bucket.
        let key = siphash13(&self.hash_key, from.source());
        if !self
            .limiter
            .allow(key, now_us, self.cfg.hello_rate_per_s, self.cfg.hello_burst)
        {
            self.stats.rate_limited_source += 1;
            return;
        }
        if !self
            .global
            .allow(now_us, self.cfg.global_rate_per_s, self.cfg.global_burst)
        {
            self.stats.rate_limited_global += 1;
            return;
        }
        if let Some(code) = self.check_fields(h) {
            if code == reject_code::VERSION {
                self.stats.rejected_version += 1;
            } else {
                self.stats.rejected_config += 1;
            }
            self.reply(
                *from,
                Body::Reject {
                    code,
                    echo: h.client_random,
                },
            );
            return;
        }
        if self.used >= self.max_slots() || !self.event_room() {
            self.stats.rejected_full += 1;
            self.reply(
                *from,
                Body::Reject {
                    code: reject_code::FULL,
                    echo: h.client_random,
                },
            );
            return;
        }
        let coarse = secs(now_us);
        let cookie = self.cookie_for(&self.secret, from, coarse, h);
        self.stats.challenges += 1;
        self.reply(*from, Body::Challenge { coarse, cookie });
    }

    fn cookie_valid(
        &mut self,
        from: &Addr,
        coarse: u32,
        cookie: u64,
        h: &HelloFields,
        now_us: u64,
    ) -> bool {
        let age = i64::from(secs(now_us)) - i64::from(coarse);
        let window = i64::from(self.cfg.cookie_freshness_s);
        if age < -window || age > window {
            self.stats.stale_cookie += 1;
            return false;
        }
        let cur = self.cookie_for(&self.secret, from, coarse, h);
        // both candidates are always computed, so timing does not tell which one matched
        let prev = self.cookie_for(&self.prev_secret, from, coarse, h);
        let ok = ct_eq_u64(cur, cookie) | (self.has_prev & ct_eq_u64(prev, cookie));
        if !ok {
            self.stats.bad_cookie += 1;
        }
        ok
    }

    fn on_response(&mut self, from: &Addr, coarse: u32, cookie: u64, h: &HelloFields, now_us: u64) {
        self.stats.response += 1;
        // The cookie covers every field and is only issued for acceptable ones, so a valid
        // cookie already means acceptable fields: there is nothing more to check here.
        if !self.cookie_valid(from, coarse, cookie, h, now_us) {
            return;
        }
        let mut reuse: Option<usize> = None;
        if let Some(i) = self.find(from) {
            let same = self.slots.get(i).map(|s| (s.client_random, s.conn.token));
            if let Some((rnd, token)) = same {
                if rnd == h.client_random {
                    // the Accept was lost on its way: say it again
                    self.stats.reaccepted += 1;
                    self.reply(*from, Body::Accept { token, echo: rnd });
                    return;
                }
            }
            // same address, a new attempt: the old connection is gone
            self.stats.replaced += 1;
            self.close(i, Closed::Replaced);
            reuse = Some(i);
        }
        let (all, pending) = self.same_source(from);
        if pending >= self.cfg.max_pending_per_source {
            // Not final: earlier half-open connections of this source will confirm or expire.
            // No reply, so the client keeps retrying and gets in when there is room.
            self.stats.deferred_pending += 1;
            return;
        }
        if all >= self.cfg.max_per_source {
            self.stats.rejected_source += 1;
            self.reply(
                *from,
                Body::Reject {
                    code: reject_code::SOURCE_LIMIT,
                    echo: h.client_random,
                },
            );
            return;
        }
        let free = reuse.or_else(|| self.slots.iter().position(|s| !s.used));
        let idx = match free {
            Some(i) if self.used < self.max_slots() && self.event_room() => i,
            _ => {
                self.stats.rejected_full += 1;
                self.reply(
                    *from,
                    Body::Reject {
                        code: reject_code::FULL,
                        echo: h.client_random,
                    },
                );
                return;
            }
        };
        let token = self.make_token(from, h.client_random);
        let addr_hash = self.addr_hash(from);
        if let Some(s) = self.slots.get_mut(idx) {
            s.used = true;
            s.confirmed = false;
            s.generation = s.generation.wrapping_add(1);
            s.addr = *from;
            s.addr_hash = addr_hash;
            s.client_random = h.client_random;
            s.created_us = now_us;
            s.conn = Conn::new(token, self.cfg.conn_config(), now_us);
            self.used += 1;
            self.stats.accepted += 1;
            self.reply(
                *from,
                Body::Accept {
                    token,
                    echo: h.client_random,
                },
            );
        }
    }

    fn on_data(&mut self, from: &Addr, dd: &wire::DataDatagram<'_>, now_us: u64) {
        self.stats.data += 1;
        let Some(idx) = self.find(from) else {
            self.stats.unknown_peer += 1;
            return;
        };
        let Some(slot) = self.slots.get_mut(idx) else {
            return;
        };
        let acc = match slot.conn.on_datagram(dd, now_us) {
            Ok(a) => a,
            Err(Refused::BadToken) => {
                self.stats.bad_token += 1;
                return;
            }
            Err(Refused::Capacity) => {
                self.stats.refused_capacity += 1;
                return;
            }
            Err(_) => {
                self.stats.dropped_replay += 1;
                return;
            }
        };
        let conn = ConnId {
            index: idx as u32,
            generation: slot.generation,
        };
        let addr = slot.addr;
        let first = !slot.confirmed;
        slot.confirmed = true;
        if first {
            self.stats.confirmed += 1;
            if !self.events.push(Event::Connected { conn, addr }) {
                self.stats.events_lost += 1;
            }
        }
        if let Some(reason) = acc.disconnect {
            self.close(idx, Closed::Remote(reason));
        }
    }

    /// Close a connection from the host side: DISCONNECT is sent three times and the slot is
    /// freed at once. `false` if the handle is stale.
    /// Закрыть соединение со стороны хозяина: DISCONNECT уходит трижды, слот освобождается сразу.
    pub fn disconnect(&mut self, conn: ConnId, reason: u8) -> bool {
        let idx = conn.index as usize;
        let Some(s) = self.slots.get_mut(idx) else {
            return false;
        };
        if !(s.used && s.generation == conn.generation) {
            return false;
        }
        let (to, token) = (s.addr, s.conn.token);
        let mut pns = [0u64; 3];
        for p in &mut pns {
            *p = s.conn.next_pn();
        }
        for pn in pns {
            self.reply(to, Body::Disconnect { token, pn, reason });
        }
        self.close(idx, Closed::Local(reason));
        true
    }

    fn close(&mut self, idx: usize, reason: Closed) {
        let Some(s) = self.slots.get_mut(idx) else {
            return;
        };
        if !s.used {
            return;
        }
        let conn = ConnId {
            index: idx as u32,
            generation: s.generation,
        };
        let announced = s.confirmed;
        s.used = false;
        s.confirmed = false;
        self.used = self.used.saturating_sub(1);
        if announced && !self.events.push(Event::Disconnected { conn, reason }) {
            self.stats.events_lost += 1;
        }
    }

    /// Drop connections that went silent. Call when [`next_deadline`](Self::next_deadline)
    /// has passed. / Снять замолчавшие соединения; звать по сроку `next_deadline`.
    pub fn handle_timeout(&mut self, now_us: u64) {
        for i in 0..N {
            let Some(s) = self.slots.get(i) else { break };
            if !s.used {
                continue;
            }
            if now_us >= self.expiry(s) {
                if s.confirmed {
                    self.stats.idle_expired += 1;
                } else {
                    self.stats.unconfirmed_expired += 1;
                }
                self.close(i, Closed::Timeout);
            } else if let Some(s) = self.slots.get_mut(i) {
                if s.conn.next_deadline().is_some_and(|t| t <= now_us) {
                    s.conn.on_timeout(now_us);
                }
            }
        }
    }

    fn encode(&self, r: &Reply, out: &mut [u8]) -> Result<usize, WriteError> {
        let channels = self.cfg.channels;
        match r.body {
            Body::Challenge { coarse, cookie } => wire::write_challenge(out, coarse, cookie),
            Body::Accept { token, echo } => {
                wire::write_accept(out, token, echo, 0, self.cfg.accept_blob.as_bytes())
            }
            Body::Reject { code, echo } => wire::write_reject(out, code, echo),
            Body::Disconnect { token, pn, reason } => {
                let mut w = DataWriter::new(out, channels.as_slice(), token, pn as u16)?;
                w.disconnect(reason)?;
                w.finish()
            }
        }
    }

    /// Next datagram to send and where: `(destination, length)`, written into `buf`
    /// (at least 1400 bytes). `None` when nothing is queued.
    /// Следующая датаграмма к отправке: `(адрес, длина)`, записана в `buf` (не меньше 1400 байт).
    pub fn poll_transmit(&mut self, buf: &mut [u8], now_us: u64) -> Option<(Addr, usize)> {
        if buf.len() < MAX_DATAGRAM {
            return None;
        }
        // handshake replies and disconnects first
        while let Some(r) = self.replies.pop() {
            if let Ok(n) = self.encode(&r, buf) {
                self.stats.bytes_out += n as u64;
                return Some((r.to, n));
            }
        }
        // then the connections, taking turns so that one busy client cannot starve the rest
        for k in 0..N {
            let i = (self.rr + k) % N;
            let Some(s) = self.slots.get_mut(i) else {
                continue;
            };
            if !s.used {
                continue;
            }
            if let Some(n) = s.conn.build(now_us, buf) {
                self.rr = (i + 1) % N;
                self.stats.bytes_out += n as u64;
                return Some((s.addr, n));
            }
        }
        None
    }

    fn slot_mut(&mut self, conn: ConnId) -> Option<&mut Slot> {
        let s = self.slots.get_mut(conn.index as usize)?;
        (s.used && s.confirmed && s.generation == conn.generation).then_some(s)
    }

    /// Queue a message for a connection. Reliable messages are either queued whole or refused
    /// with [`SendError::Full`]; the host decides what to do about a peer that cannot keep up.
    /// Поставить сообщение соединению в очередь. Надёжное либо встаёт целиком, либо отклоняется
    /// с [`SendError::Full`]; что делать с отстающим пиром, решает хозяин.
    pub fn send(&mut self, conn: ConnId, ch: u8, data: &[u8]) -> Result<(), SendError> {
        self.slot_mut(conn)
            .ok_or(SendError::NotConnected)?
            .conn
            .send(ch, data)
    }

    /// The next received message from any connection, written into `buf` (at least
    /// [`MSG_MAX`] bytes). Connections are served in turn. `None` when nothing is waiting.
    /// Следующее принятое сообщение от любого соединения; соединения обслуживаются по кругу.
    pub fn poll_recv(&mut self, buf: &mut [u8]) -> Option<Received> {
        if buf.len() < MSG_MAX {
            return None;
        }
        for k in 0..N {
            let i = (self.rr + k) % N;
            let Some(s) = self.slots.get_mut(i) else {
                continue;
            };
            if !(s.used && s.confirmed) {
                continue;
            }
            if let Some(d) = s.conn.poll_recv() {
                let payload = d.payload();
                if let Some(dst) = buf.get_mut(..payload.len()) {
                    dst.copy_from_slice(payload);
                }
                return Some(Received {
                    conn: ConnId {
                        index: i as u32,
                        generation: s.generation,
                    },
                    ch: d.ch,
                    len: payload.len(),
                });
            }
        }
        None
    }

    /// Counters, RTT and traffic of one connection. / Счётчики, RTT и трафик соединения.
    pub fn conn_stats(&self, conn: ConnId) -> Option<ConnStats> {
        let s = self.slots.get(conn.index as usize)?;
        (s.used && s.confirmed && s.generation == conn.generation).then(|| s.conn.stats())
    }
}
