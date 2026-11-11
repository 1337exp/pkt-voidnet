//! State both ends keep for an established connection: token, receive window, send counter.
//! Состояние, которое обе стороны держат для установленного соединения.

use crate::siphash::ct_eq_u64;
use crate::window::{Class, RecvWindow};
use crate::wire::{DataDatagram, Frame};

/// Why a DATA datagram did not count. / Почему DATA не засчитана.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refused {
    BadToken,
    /// Packet number not representable (negative after reconstruction).
    BadNumber,
    Duplicate,
    TooOld,
}

/// What an accepted DATA datagram contained that the connection layer acts on.
/// Что в принятой DATA требует действий соединения.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Accepted {
    pub ping: bool,
    pub disconnect: Option<u8>,
    pub ack_eliciting: bool,
}

/// Token, receive window and send counter of one connection.
/// Токен, окно приёма и счётчик отправки одного соединения.
#[derive(Clone, Copy, Debug)]
pub struct Peer {
    pub token: u64,
    win: RecvWindow,
    tx_pn: u64,
    pub last_recv_us: u64,
}

impl Peer {
    pub fn new(token: u64, now_us: u64) -> Self {
        Self {
            token,
            win: RecvWindow::new(),
            tx_pn: 0,
            last_recv_us: now_us,
        }
    }

    /// Check a DATA datagram and, only if it is authentic and new, record it. Failed
    /// authentication changes nothing (invariant I6).
    /// Проверить DATA и только для подлинной и новой записать её. Неудачная проверка
    /// подлинности ничего не меняет (инвариант I6).
    pub fn receive(&mut self, dd: &DataDatagram<'_>, now_us: u64) -> Result<Accepted, Refused> {
        if !ct_eq_u64(dd.token, self.token) {
            return Err(Refused::BadToken);
        }
        let pn = self.win.reconstruct(dd.pn).ok_or(Refused::BadNumber)?;
        match self.win.classify(pn) {
            Class::Duplicate => return Err(Refused::Duplicate),
            Class::TooOld => return Err(Refused::TooOld),
            Class::New => {}
        }
        self.win.mark(pn);
        self.last_recv_us = self.last_recv_us.max(now_us);
        let mut out = Accepted {
            ping: false,
            disconnect: None,
            ack_eliciting: false,
        };
        for f in dd.frames() {
            out.ack_eliciting |= f.ack_eliciting();
            match f {
                Frame::Ping => out.ping = true,
                Frame::Disconnect { reason } => out.disconnect = Some(reason),
                _ => {}
            }
        }
        Ok(out)
    }

    /// The next packet number to send; the wire carries its low 16 bits.
    /// Следующий номер для отправки; по проводу идут его младшие 16 бит.
    pub fn next_pn(&mut self) -> u64 {
        let pn = self.tx_pn;
        self.tx_pn = self.tx_pn.wrapping_add(1);
        pn
    }
}
