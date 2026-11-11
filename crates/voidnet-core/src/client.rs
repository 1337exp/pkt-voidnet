//! Client side of the handshake (stage 2): HELLO, RESPONSE, ACCEPT, with resends, a handshake
//! timeout, and confirmation of the connection by the first DATA.
//!
//! Клиентская сторона рукопожатия (этап 2): HELLO, RESPONSE, ACCEPT, с повторами, таймаутом
//! рукопожатия и подтверждением соединения первой DATA.

use crate::addr::Addr;
use crate::config::{Blob, ClientConfig, ConfigError};
use crate::conn::{Conn, ConnStats, SendError, MSG_MAX};
use crate::ring::Ring;
use crate::server::Closed;
use crate::wire::{
    self, DataWriter, Datagram, HelloFields, WriteError, MAX_DATAGRAM, WIRE_VERSION,
};

/// Why a connection attempt failed. / Почему попытка соединения не удалась.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Failed {
    /// The server answered REJECT with this code (see `wire::reject_code`).
    Rejected(u8),
    /// No answer in time. / Ответа не было вовремя.
    Timeout,
}

/// What the host learns about the connection. / Что узнаёт хозяин о соединении.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ClientEvent {
    /// The server accepted; `blob` is its application data from ACCEPT.
    Connected {
        blob: Blob,
        caps: u32,
    },
    Failed(Failed),
    Disconnected(Closed),
}

impl Default for ClientEvent {
    fn default() -> Self {
        ClientEvent::Failed(Failed::Timeout)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
enum State {
    Idle,
    Hello,
    Responding,
    Connected,
    Closed,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(u8)]
enum Out {
    #[default]
    Hello,
    Response,
    Disconnect {
        pn: u64,
        reason: u8,
    },
}

/// The client. One connection at a time. / Клиент. Одно соединение за раз.
pub struct Client {
    cfg: ClientConfig,
    state: State,
    server: Addr,
    random: u64,
    started_us: u64,
    last_tx_us: u64,
    coarse: u32,
    cookie: u64,
    response_sends: u8,
    conn: Conn,
    server_seen: bool,
    out: Ring<Out, 8>,
    events: Ring<ClientEvent, 8>,
}

impl Client {
    pub fn new(cfg: ClientConfig) -> Result<Self, ConfigError> {
        cfg.validate()?;
        Ok(Self {
            cfg,
            state: State::Idle,
            server: Addr::default(),
            random: 0,
            started_us: 0,
            last_tx_us: 0,
            coarse: 0,
            cookie: 0,
            response_sends: 0,
            conn: Conn::new(0, cfg.conn_config(), 0),
            server_seen: false,
            out: Ring::new(),
            events: Ring::new(),
        })
    }

    /// Put the client into the state [`new`](Self::new) builds, in place (see `Server::reset`).
    /// Привести клиента в состояние `new` на месте (см. `Server::reset`).
    pub fn reset(&mut self, cfg: ClientConfig) -> Result<(), ConfigError> {
        cfg.validate()?;
        self.cfg = cfg;
        self.state = State::Idle;
        self.server = Addr::default();
        self.random = 0;
        self.started_us = 0;
        self.last_tx_us = 0;
        self.coarse = 0;
        self.cookie = 0;
        self.response_sends = 0;
        self.conn.reset(0, cfg.conn_config(), 0);
        self.server_seen = false;
        self.out.reset();
        self.events.reset();
        Ok(())
    }

    /// Begin a connection attempt. `random` must be 8 fresh random bytes from the host.
    /// Returns `false` if an attempt is already running. / Начать соединение; `random` даёт хозяин.
    pub fn connect(&mut self, server: Addr, random: u64, now_us: u64) -> bool {
        if matches!(
            self.state,
            State::Hello | State::Responding | State::Connected
        ) {
            return false;
        }
        self.state = State::Hello;
        self.server = server;
        self.random = random;
        self.started_us = now_us;
        self.last_tx_us = now_us;
        self.server_seen = false;
        self.response_sends = 0;
        self.out = Ring::new();
        self.out.push(Out::Hello);
        true
    }

    pub fn is_connected(&self) -> bool {
        self.state == State::Connected
    }

    pub fn poll_event(&mut self) -> Option<ClientEvent> {
        self.events.pop()
    }

    fn fields(&self) -> HelloFields {
        HelloFields {
            wire_version: WIRE_VERSION,
            protocol_id: self.cfg.protocol_id,
            app_version: self.cfg.app_version,
            config_hash: self.cfg.config_hash(),
            client_random: self.random,
            caps: 0,
        }
    }

    fn fail(&mut self, why: Failed) {
        self.state = State::Closed;
        self.events.push(ClientEvent::Failed(why));
    }

    /// Feed a datagram that arrived from `from`. Datagrams from any other address are ignored.
    /// Принять датаграмму. Датаграммы с чужого адреса игнорируются.
    pub fn handle_datagram(&mut self, from: &Addr, data: &[u8], now_us: u64) {
        if *from != self.server || self.state == State::Idle || self.state == State::Closed {
            return;
        }
        let channels = self.cfg.channels;
        let Ok(d) = wire::parse(data, channels.as_slice()) else {
            return;
        };
        match d {
            Datagram::Challenge { coarse, cookie } if self.state == State::Hello => {
                self.coarse = coarse;
                self.cookie = cookie;
                self.state = State::Responding;
                self.response_sends = 1;
                self.last_tx_us = now_us;
                self.out.push(Out::Response);
            }
            Datagram::Accept {
                token,
                echo,
                caps,
                blob,
            } if echo == self.random && matches!(self.state, State::Hello | State::Responding) => {
                self.state = State::Connected;
                self.conn = Conn::new(token, self.cfg.conn_config(), now_us);
                self.last_tx_us = now_us;
                let blob = Blob::new(blob).unwrap_or_default();
                self.events.push(ClientEvent::Connected { blob, caps });
                // the first authentic DATA confirms the connection to the server
                self.conn.queue_ping();
            }
            Datagram::Reject { code, echo }
                if echo == self.random
                    && matches!(self.state, State::Hello | State::Responding) =>
            {
                self.fail(Failed::Rejected(code));
            }
            Datagram::Data(dd) if self.state == State::Connected => {
                if let Ok(acc) = self.conn.on_datagram(&dd, now_us) {
                    self.server_seen = true;
                    if let Some(reason) = acc.disconnect {
                        self.state = State::Closed;
                        self.events
                            .push(ClientEvent::Disconnected(Closed::Remote(reason)));
                    }
                }
            }
            _ => {}
        }
    }

    /// Close the connection: DISCONNECT is sent three times. / Закрыть: DISCONNECT уходит трижды.
    pub fn disconnect(&mut self, reason: u8) {
        if self.state == State::Connected {
            for _ in 0..3 {
                let pn = self.conn.next_pn();
                self.out.push(Out::Disconnect { pn, reason });
            }
            self.events
                .push(ClientEvent::Disconnected(Closed::Local(reason)));
        }
        if matches!(
            self.state,
            State::Hello | State::Responding | State::Connected
        ) {
            self.state = State::Closed;
        }
    }

    fn tick(&mut self, now_us: u64) {
        let waited = now_us.saturating_sub(self.started_us);
        let since_tx = now_us.saturating_sub(self.last_tx_us);
        match self.state {
            State::Hello | State::Responding => {
                if waited >= self.cfg.handshake_timeout_us {
                    self.fail(Failed::Timeout);
                } else if since_tx >= self.cfg.retry_interval_us {
                    self.last_tx_us = now_us;
                    if self.state == State::Responding
                        && self.response_sends <= self.cfg.response_retries
                    {
                        self.response_sends += 1;
                        self.out.push(Out::Response);
                    } else {
                        // the cookie did not work (forged challenge or stale): start over
                        self.state = State::Hello;
                        self.out.push(Out::Hello);
                    }
                }
            }
            State::Connected => {
                if !self.server_seen && waited >= self.cfg.handshake_timeout_us {
                    self.state = State::Closed;
                    self.events.push(ClientEvent::Failed(Failed::Timeout));
                } else if self.server_seen
                    && now_us.saturating_sub(self.conn.last_recv_us) >= self.cfg.idle_timeout_us
                {
                    self.state = State::Closed;
                    self.events.push(ClientEvent::Disconnected(Closed::Timeout));
                } else if self.conn.next_deadline().is_some_and(|t| t <= now_us) {
                    self.conn.on_timeout(now_us);
                }
            }
            State::Idle | State::Closed => {}
        }
    }

    /// When the host should call [`poll_transmit`](Self::poll_transmit) next even if nothing
    /// arrives. / Когда хозяину позвать `poll_transmit`, даже если ничего не пришло.
    pub fn next_deadline(&self) -> Option<u64> {
        match self.state {
            State::Hello | State::Responding => Some(
                self.last_tx_us
                    .saturating_add(self.cfg.retry_interval_us)
                    .min(
                        self.started_us
                            .saturating_add(self.cfg.handshake_timeout_us),
                    ),
            ),
            State::Connected => {
                let end = if self.server_seen {
                    self.conn
                        .last_recv_us
                        .saturating_add(self.cfg.idle_timeout_us)
                } else {
                    self.started_us
                        .saturating_add(self.cfg.handshake_timeout_us)
                };
                Some(self.conn.next_deadline().map_or(end, |t| t.min(end)))
            }
            State::Idle | State::Closed => None,
        }
    }

    fn encode(&self, o: &Out, buf: &mut [u8]) -> Result<usize, WriteError> {
        let channels = self.cfg.channels;
        match *o {
            Out::Hello => wire::write_hello(buf, &self.fields()),
            Out::Response => wire::write_response(buf, self.coarse, self.cookie, &self.fields()),
            Out::Disconnect { pn, reason } => {
                let mut w = DataWriter::new(buf, channels.as_slice(), self.conn.token, pn as u16)?;
                w.disconnect(reason)?;
                w.finish()
            }
        }
    }

    /// Next datagram to send: `(destination, length)` written into `buf` (at least 1400 bytes).
    /// Следующая датаграмма: `(адрес, длина)` в `buf` (не меньше 1400 байт).
    pub fn poll_transmit(&mut self, buf: &mut [u8], now_us: u64) -> Option<(Addr, usize)> {
        self.tick(now_us);
        if buf.len() < MAX_DATAGRAM {
            return None;
        }
        while let Some(o) = self.out.pop() {
            if let Ok(n) = self.encode(&o, buf) {
                return Some((self.server, n));
            }
        }
        if self.state == State::Connected {
            if let Some(n) = self.conn.build(now_us, buf) {
                return Some((self.server, n));
            }
        }
        None
    }

    /// Queue a message for the server. See `Server::send`. / Поставить сообщение серверу в очередь.
    pub fn send(&mut self, ch: u8, data: &[u8]) -> Result<(), SendError> {
        if self.state != State::Connected {
            return Err(SendError::NotConnected);
        }
        self.conn.send(ch, data)
    }

    /// The next received message, written into `buf` (at least [`MSG_MAX`] bytes): `(channel,
    /// length)`. / Следующее принятое сообщение: `(канал, длина)`.
    pub fn poll_recv(&mut self, buf: &mut [u8]) -> Option<(u8, usize)> {
        if buf.len() < MSG_MAX || self.state != State::Connected {
            return None;
        }
        let d = self.conn.poll_recv()?;
        let payload = d.payload();
        if let Some(dst) = buf.get_mut(..payload.len()) {
            dst.copy_from_slice(payload);
        }
        Some((d.ch, payload.len()))
    }

    /// Counters, RTT and traffic of the connection. / Счётчики, RTT и трафик соединения.
    pub fn conn_stats(&self) -> Option<ConnStats> {
        (self.state == State::Connected).then(|| self.conn.stats())
    }
}
