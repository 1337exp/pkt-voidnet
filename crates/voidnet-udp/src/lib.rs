//! pkt-voidnet over `std::net::UdpSocket`: everything a Rust host needs around the sans-IO
//! core. The core decides *what* to send and when; this crate owns the socket, the clock,
//! the random bytes and the timers, and gives the host two small types: [`UdpServer`] and
//! [`UdpClient`].
//!
//! The usual loop of a host:
//!
//! ```text
//! loop {
//!     net.pump(Some(time_left_in_tick))?;     // receive, run timers, send what is due
//!     while let Some(e) = net.poll_event() { ... }
//!     while let Some(m) = net.poll_recv(&mut buf) { ... }
//!     net.send(conn, ch, bytes)?; net.flush(conn)?;   // flush puts it on the wire now
//! }
//! ```
//!
//! pkt-voidnet поверх `std::net::UdpSocket`: всё, что нужно хозяину на Rust вокруг ядра без
//! ввода-вывода. Ядро решает, *что* и когда отправлять; этот крейт держит сокет, часы,
//! случайные байты и таймеры и даёт два небольших типа: [`UdpServer`] и [`UdpClient`].

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

pub use voidnet_core as core;
use voidnet_core::conn::MSG_MAX;
use voidnet_core::{
    Addr, Client, ClientConfig, ClientEvent, ConnId, ConnStats, Event, Received, SendError, Server,
    ServerConfig,
};

/// A receive buffer for [`UdpServer::poll_recv`] and [`UdpClient::poll_recv`].
/// Буфер приёма для `poll_recv`.
pub const RECV_BUF: usize = MSG_MAX;

/// Most datagrams read from the socket in one [`pump`](UdpServer::pump), so that a flood
/// cannot keep the host inside the receive loop forever.
/// Сколько датаграмм читается из сокета за один `pump`: поток мусора не удержит хозяина в
/// цикле приёма навсегда.
pub const MAX_RECV_PER_PUMP: usize = 4096;

/// The core's address for a socket address: 16 bytes of IPv6 (IPv4 is mapped), then the port,
/// with the IP as the source for per-source limits.
/// Адрес ядра для адреса сокета: 16 байт IPv6 (IPv4 отображается), затем порт; источник для
/// лимитов это IP.
pub fn to_addr(sa: SocketAddr) -> Addr {
    let ip = match sa.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    let mut b = [0u8; 18];
    b[..16].copy_from_slice(&ip.octets());
    b[16..].copy_from_slice(&sa.port().to_be_bytes());
    // 18 bytes with a source of 16 is always a valid address
    Addr::new(&b, 16).unwrap_or_default()
}

/// The socket address behind an address made by [`to_addr`]. `None` for any other shape.
/// Адрес сокета за адресом из [`to_addr`]. `None` для любой другой формы.
pub fn to_socket_addr(a: &Addr) -> Option<SocketAddr> {
    let b = a.as_bytes();
    if b.len() != 18 {
        return None;
    }
    let mut ip = [0u8; 16];
    ip.copy_from_slice(b.get(..16)?);
    let port = u16::from_be_bytes([*b.get(16)?, *b.get(17)?]);
    let v6 = Ipv6Addr::from(ip);
    let ip = match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    };
    Some(SocketAddr::new(ip, port))
}

/// 8 random bytes from the operating system (through the keys `std` draws for its hash
/// maps), mixed with the time. Good for cookies and connection attempts; this crate has no
/// dependency for randomness on purpose.
/// 8 случайных байт от ОС (через ключи, которые `std` берёт для своих хеш-таблиц), смешанные
/// со временем. Зависимости ради случайности здесь нет намеренно.
pub fn random_u64() -> u64 {
    let mut h = RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    h.finish()
}

fn random_bytes<const K: usize>() -> [u8; K] {
    let mut out = [0u8; K];
    for chunk in out.chunks_mut(8) {
        let r = random_u64().to_le_bytes();
        for (d, s) in chunk.iter_mut().zip(r) {
            *d = s;
        }
    }
    out
}

/// Errors that only say "nothing to read now" or "a previous send bounced" and must not stop
/// the loop. On Windows a UDP socket reports `ConnectionReset` on the *next receive* after a
/// datagram went to a closed port; that is news about someone else, not about this socket.
/// Ошибки, которые значат лишь «сейчас читать нечего» или «прошлая отправка отскочила».
/// В Windows UDP-сокет сообщает `ConnectionReset` при *следующем чтении* после отправки на
/// закрытый порт: это новость о ком-то другом, а не об этом сокете.
fn soft(e: &io::Error) -> Soft {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Soft::Empty,
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::Interrupted => Soft::Skip,
        _ => Soft::Hard,
    }
}

enum Soft {
    Empty,
    Skip,
    Hard,
}

/// Read one datagram: wait up to `wait` for the first one, never wait when `wait` is `None`.
/// Прочитать одну датаграмму: ждать не дольше `wait`; при `None` не ждать вовсе.
fn recv_one(
    socket: &UdpSocket,
    buf: &mut [u8],
    wait: Option<Duration>,
) -> io::Result<Option<(usize, SocketAddr)>> {
    match wait {
        // a zero timeout is an error for the socket API, treat it as "do not wait"
        Some(d) if !d.is_zero() => {
            socket.set_nonblocking(false)?;
            socket.set_read_timeout(Some(d))?;
        }
        _ => socket.set_nonblocking(true)?,
    }
    loop {
        match socket.recv_from(buf) {
            Ok(v) => return Ok(Some(v)),
            Err(e) => match soft(&e) {
                Soft::Empty => return Ok(None),
                Soft::Skip => {
                    // after a bounce do not wait again: the caller's time budget is spent once
                    socket.set_nonblocking(true)?;
                }
                Soft::Hard => return Err(e),
            },
        }
    }
}

fn send_soft(socket: &UdpSocket, data: &[u8], to: SocketAddr) -> io::Result<()> {
    match socket.send_to(data, to) {
        Ok(_) => Ok(()),
        // a full send buffer or a bounce loses one datagram, which the core already survives
        Err(e) if !matches!(soft(&e), Soft::Hard) => Ok(()),
        Err(e) => Err(e),
    }
}

/// A voidnet server on a UDP socket: `N` connection slots, `R` rate-limit entries, `E` event
/// slots (`E >= 2N + 2`), as in [`Server`].
/// Сервер voidnet на UDP-сокете: `N` слотов соединений, `R` записей лимитера, `E` мест под
/// события (`E >= 2N + 2`), как у [`Server`].
pub struct UdpServer<const N: usize, const R: usize, const E: usize> {
    socket: UdpSocket,
    core: Box<Server<N, R, E>>,
    epoch: Instant,
    next_rotation_us: u64,
    rotation_us: u64,
    buf: Box<[u8; 2048]>,
}

/// The server state is large (about 100 KB per slot) and the core cannot build it in place
/// without `unsafe`, so it is allocated zeroed on the heap and brought to life by
/// `Server::reset`, exactly as the C ABI does with the host's memory.
/// Состояние сервера большое (около 100 КБ на слот), поэтому оно выделяется в куче обнулённым
/// и оживляется через `Server::reset`, как это делает C ABI с памятью хозяина.
fn boxed_server<const N: usize, const R: usize, const E: usize>(
    cfg: ServerConfig,
    seed: [u8; 32],
    now_us: u64,
) -> io::Result<Box<Server<N, R, E>>> {
    let layout = std::alloc::Layout::new::<Server<N, R, E>>();
    // SAFETY: the layout has a non-zero size (a server holds its configuration), the block is
    // zeroed, and every type inside `Server` is valid as all-zero bytes: that is a documented
    // invariant of voidnet-core (`#[repr(u8)]` enums starting at 0, no `Option` or references
    // in the state), relied on and checked under Miri by voidnet-ffi. `Box::from_raw` takes
    // back exactly the block the global allocator gave for this layout.
    let mut b = unsafe {
        let p = std::alloc::alloc_zeroed(layout).cast::<Server<N, R, E>>();
        if p.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Box::from_raw(p)
    };
    b.reset(cfg, seed, now_us)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e:?}")))?;
    Ok(b)
}

impl<const N: usize, const R: usize, const E: usize> UdpServer<N, R, E> {
    /// Bind a socket and start a server on it. / Занять сокет и запустить на нём сервер.
    pub fn bind(addr: impl ToSocketAddrs, cfg: ServerConfig) -> io::Result<Self> {
        const { assert!(E >= 2 * N + 2, "event queue must hold two events per slot") };
        let socket = UdpSocket::bind(addr)?;
        let epoch = Instant::now();
        Ok(Self {
            socket,
            core: boxed_server(cfg, random_bytes(), 0)?,
            epoch,
            next_rotation_us: cfg.rotation_interval_us,
            rotation_us: cfg.rotation_interval_us,
            buf: Box::new([0; 2048]),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Microseconds since the server started: the clock the core runs on.
    /// Микросекунды с запуска сервера: часы, по которым живёт ядро.
    pub fn now_us(&self) -> u64 {
        self.epoch.elapsed().as_micros() as u64
    }

    /// How long until the core wants to be called again, if it wants at all.
    /// Через сколько ядро хочет, чтобы его позвали снова (если хочет).
    pub fn until_deadline(&self) -> Option<Duration> {
        let now = self.now_us();
        self.core
            .next_deadline()
            .map(|t| Duration::from_micros(t.saturating_sub(now)))
    }

    /// One round of I/O: read what has arrived (waiting up to `wait` for the first datagram, and
    /// not past the core's next timer), run the timers that are due, send what is ready.
    /// Один круг ввода-вывода: прочитать пришедшее (ждать первую датаграмму не дольше `wait` и
    /// не дольше ближайшего таймера ядра), выполнить таймеры, отправить готовое.
    pub fn pump(&mut self, wait: Option<Duration>) -> io::Result<()> {
        let mut wait = match (wait, self.until_deadline()) {
            (Some(w), Some(d)) => Some(w.min(d)),
            (w, _) => w,
        };
        for _ in 0..MAX_RECV_PER_PUMP {
            let Some((n, from)) = recv_one(&self.socket, &mut self.buf[..], wait)? else {
                break;
            };
            wait = None;
            let now = self.now_us();
            if let Some(data) = self.buf.get(..n) {
                self.core.handle_datagram(&to_addr(from), data, now);
            }
        }
        self.service()
    }

    /// Run the timers and send everything that is ready, without reading the socket. Called
    /// by [`pump`](Self::pump); call it yourself right after `flush` to put the datagram on
    /// the wire without waiting for the next pump.
    /// Выполнить таймеры и отправить готовое, не читая сокет. Зови сразу после `flush`, чтобы
    /// датаграмма ушла, не дожидаясь следующего `pump`.
    pub fn service(&mut self) -> io::Result<()> {
        let now = self.now_us();
        if now >= self.next_rotation_us {
            self.core.rotate_secret(random_bytes(), now);
            self.next_rotation_us = now.saturating_add(self.rotation_us);
        }
        self.core.handle_timeout(now);
        while let Some((to, n)) = self.core.poll_transmit(&mut self.buf[..], now) {
            if let (Some(sa), Some(data)) = (to_socket_addr(&to), self.buf.get(..n)) {
                send_soft(&self.socket, data, sa)?;
            }
        }
        Ok(())
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.core.poll_event()
    }

    /// The next received message, written into `buf` (at least [`RECV_BUF`] bytes).
    /// Следующее принятое сообщение, записанное в `buf` (не меньше [`RECV_BUF`] байт).
    pub fn poll_recv(&mut self, buf: &mut [u8]) -> Option<Received> {
        self.core.poll_recv(buf)
    }

    /// Queue a message. Nothing leaves before [`flush`](Self::flush) or a timer.
    /// Поставить сообщение в очередь. До `flush` или таймера ничего не уходит.
    pub fn send(&mut self, conn: ConnId, ch: u8, data: &[u8]) -> Result<(), SendError> {
        self.core.send(conn, ch, data)
    }

    /// Mark what is queued for `conn` to be sent by the next [`service`](Self::service) or
    /// [`pump`](Self::pump).
    /// Пометить очередь соединения к отправке ближайшим `service` или `pump`.
    pub fn flush(&mut self, conn: ConnId) -> Result<(), SendError> {
        self.core.flush(conn)
    }

    pub fn disconnect(&mut self, conn: ConnId, reason: u8) -> bool {
        self.core.disconnect(conn, reason)
    }

    pub fn conn_stats(&self, conn: ConnId) -> Option<ConnStats> {
        self.core.conn_stats(conn)
    }

    pub fn conn_addr(&self, conn: ConnId) -> Option<SocketAddr> {
        self.core.conn_addr(conn).and_then(|a| to_socket_addr(&a))
    }

    /// The core itself, for what this wrapper does not cover (statistics, limits).
    /// Само ядро, для того, что эта обёртка не покрывает.
    pub fn core(&mut self) -> &mut Server<N, R, E> {
        &mut self.core
    }
}

/// A voidnet client on a UDP socket. One connection at a time.
/// Клиент voidnet на UDP-сокете. Одно соединение за раз.
pub struct UdpClient {
    socket: UdpSocket,
    core: Box<Client>,
    epoch: Instant,
    server: SocketAddr,
    server_addr: Addr,
    buf: Box<[u8; 2048]>,
}

impl UdpClient {
    /// Open a socket and start connecting to `server`. The answer comes as an event after
    /// some [`pump`](Self::pump) calls.
    /// Открыть сокет и начать соединение с `server`. Ответ придёт событием после нескольких
    /// вызовов `pump`.
    pub fn connect(server: impl ToSocketAddrs, cfg: ClientConfig) -> io::Result<Self> {
        let server = server
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no server address"))?;
        let local: SocketAddr = match server {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = UdpSocket::bind(local)?;
        let mut core = Box::new(
            Client::new(cfg)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e:?}")))?,
        );
        let server_addr = to_addr(server);
        core.connect(server_addr, random_u64(), 0);
        let mut c = Self {
            socket,
            core,
            epoch: Instant::now(),
            server,
            server_addr,
            buf: Box::new([0; 2048]),
        };
        c.service()?;
        Ok(c)
    }

    pub fn now_us(&self) -> u64 {
        self.epoch.elapsed().as_micros() as u64
    }

    pub fn is_connected(&self) -> bool {
        self.core.is_connected()
    }

    pub fn until_deadline(&self) -> Option<Duration> {
        let now = self.now_us();
        self.core
            .next_deadline()
            .map(|t| Duration::from_micros(t.saturating_sub(now)))
    }

    /// A second handle to the same socket, for a host that blocks on it in its own thread and
    /// hands what it reads to [`feed`](Self::feed).
    /// Второй дескриптор того же сокета: для хозяина, который ждёт на нём в своём потоке и
    /// отдаёт прочитанное в [`feed`](Self::feed).
    pub fn try_clone_socket(&self) -> io::Result<UdpSocket> {
        self.socket.try_clone()
    }

    /// Hand over a datagram the host read from the socket itself, then run the timers and send.
    /// Datagrams that did not come from the server are ignored.
    /// Отдать датаграмму, которую хозяин сам прочитал из сокета; затем таймеры и отправка.
    pub fn feed(&mut self, from: SocketAddr, data: &[u8]) -> io::Result<()> {
        if from == self.server {
            let now = self.now_us();
            self.core.handle_datagram(&self.server_addr, data, now);
        }
        self.service()
    }

    /// One round of I/O, see [`UdpServer::pump`]. / Один круг ввода-вывода.
    pub fn pump(&mut self, wait: Option<Duration>) -> io::Result<()> {
        let mut wait = match (wait, self.until_deadline()) {
            (Some(w), Some(d)) => Some(w.min(d)),
            (w, _) => w,
        };
        for _ in 0..MAX_RECV_PER_PUMP {
            let Some((n, from)) = recv_one(&self.socket, &mut self.buf[..], wait)? else {
                break;
            };
            wait = None;
            if from != self.server {
                continue;
            }
            let now = self.now_us();
            if let Some(data) = self.buf.get(..n) {
                self.core.handle_datagram(&self.server_addr, data, now);
            }
        }
        self.service()
    }

    /// Run the timers and send everything that is ready. / Выполнить таймеры и отправить готовое.
    pub fn service(&mut self) -> io::Result<()> {
        let now = self.now_us();
        while let Some((_, n)) = self.core.poll_transmit(&mut self.buf[..], now) {
            if let Some(data) = self.buf.get(..n) {
                send_soft(&self.socket, data, self.server)?;
            }
        }
        Ok(())
    }

    pub fn poll_event(&mut self) -> Option<ClientEvent> {
        self.core.poll_event()
    }

    /// The next received message: `(channel, length)`, written into `buf` (at least
    /// [`RECV_BUF`] bytes). / Следующее принятое сообщение: `(канал, длина)`.
    pub fn poll_recv(&mut self, buf: &mut [u8]) -> Option<(u8, usize)> {
        self.core.poll_recv(buf)
    }

    pub fn send(&mut self, ch: u8, data: &[u8]) -> Result<(), SendError> {
        self.core.send(ch, data)
    }

    pub fn flush(&mut self) -> Result<(), SendError> {
        self.core.flush()
    }

    /// Queue, flush and put on the wire in one call: what a client does with a click.
    /// Поставить, пометить и отправить одним вызовом: то, что клиент делает с кликом.
    pub fn send_now(&mut self, ch: u8, data: &[u8]) -> io::Result<Result<(), SendError>> {
        if let Err(e) = self.core.send(ch, data) {
            return Ok(Err(e));
        }
        let _ = self.core.flush();
        self.service()?;
        Ok(Ok(()))
    }

    /// Close the connection and send the three DISCONNECT datagrams now.
    /// Закрыть соединение и сразу отправить три DISCONNECT.
    pub fn disconnect(&mut self, reason: u8) -> io::Result<()> {
        self.core.disconnect(reason);
        self.service()
    }

    pub fn conn_stats(&self) -> Option<ConnStats> {
        self.core.conn_stats()
    }

    pub fn core(&mut self) -> &mut Client {
        &mut self.core
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_round_trip() {
        for s in ["127.0.0.1:7000", "10.1.2.3:65535", "[::1]:9", "[2001:db8::7]:4242"] {
            let sa: SocketAddr = s.parse().unwrap();
            let a = to_addr(sa);
            assert_eq!(a.as_bytes().len(), 18);
            assert_eq!(a.source().len(), 16);
            assert_eq!(to_socket_addr(&a), Some(sa), "{s}");
        }
    }

    #[test]
    fn ipv4_address_matches_the_core_form() {
        let sa: SocketAddr = "1.2.3.4:100".parse().unwrap();
        assert_eq!(to_addr(sa), Addr::from_ipv4([1, 2, 3, 4], 100));
    }

    #[test]
    fn foreign_shapes_have_no_socket_address() {
        assert_eq!(to_socket_addr(&Addr::new(&[1, 2, 3, 4], 4).unwrap()), None);
    }

    #[test]
    fn random_values_differ() {
        let a: [u8; 32] = random_bytes();
        let b: [u8; 32] = random_bytes();
        assert_ne!(a, b);
        assert_ne!(a[..8], a[8..16]);
    }
}
