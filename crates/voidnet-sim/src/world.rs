//! A small world for scenario tests: one server, any number of clients, a lossy link in each
//! direction per client, and a virtual clock. The real state machines run unmodified.
//! Маленький мир для сценариев: сервер, клиенты, канал с потерями в каждую сторону, виртуальные
//! часы. Настоящие автоматы работают без изменений.

use crate::{Link, Params, Pcg32, TraceHash};
use voidnet_core::{Addr, Client, ClientConfig, ClientEvent, Event, Server, ServerConfig};

/// One client with its two links. / Клиент и два его канала.
pub struct Peer {
    pub client: Client,
    pub addr: Addr,
    /// client to server / от клиента к серверу
    pub up: Link,
    /// server to client / от сервера к клиенту
    pub down: Link,
    pub events: Vec<ClientEvent>,
}

/// The world. `tick_us` is the time step. / Мир. `tick_us` это шаг времени.
pub struct World<const N: usize, const R: usize, const E: usize> {
    pub now: u64,
    pub tick_us: u64,
    pub server: Server<N, R, E>,
    pub peers: Vec<Peer>,
    pub server_events: Vec<Event>,
    /// Datagrams the server sent to addresses that are not clients of this world (spoofed
    /// sources, the attacker). / Что сервер отправил на адреса, которых нет среди клиентов.
    pub stray: Vec<(Addr, Vec<u8>)>,
    pub rng: Pcg32,
    next_rotation: u64,
    rotation_us: u64,
    /// When false the world does not drain `Server::poll_event` by itself.
    pub drain_events: bool,
    /// At most this many datagrams leave the server per tick (a host with a limited send
    /// budget); `None` means no limit.
    pub server_budget: Option<usize>,
}

impl<const N: usize, const R: usize, const E: usize> World<N, R, E> {
    pub fn new(cfg: ServerConfig, seed: u64) -> Self {
        let mut rng = Pcg32::new(seed, 7);
        let mut s = [0u8; 32];
        for c in s.chunks_mut(8) {
            c.copy_from_slice(&rng.next_u64().to_le_bytes());
        }
        let now = 1_000_000_000;
        Self {
            now,
            tick_us: 1_000,
            server: Server::new(cfg, s, now).expect("valid server config"),
            peers: Vec::new(),
            server_events: Vec::new(),
            stray: Vec::new(),
            next_rotation: now + cfg.rotation_interval_us,
            rotation_us: cfg.rotation_interval_us,
            rng,
            drain_events: true,
            server_budget: None,
        }
    }

    /// Add a client and start its connection attempt. / Добавить клиента и начать соединение.
    pub fn add_client(&mut self, addr: Addr, cfg: ClientConfig, link: Params) -> usize {
        let seed = self.rng.next_u64();
        let mut c = Client::new(cfg).expect("valid client config");
        let random = self.rng.next_u64();
        c.connect(self.server_addr(), random, self.now);
        self.peers.push(Peer {
            client: c,
            addr,
            up: Link::new(link.clone(), seed),
            down: Link::new(link, seed ^ 0xA5A5),
            events: Vec::new(),
        });
        self.peers.len() - 1
    }

    /// The server's address in this world. / Адрес сервера в этом мире.
    pub fn server_addr(&self) -> Addr {
        Addr::from_ipv4([10, 255, 255, 1], 7000)
    }

    /// Replace a client by a fresh one on the same address (same links), as after a restart.
    /// Заменить клиента новым на том же адресе (те же каналы), как после перезапуска.
    pub fn restart_client(&mut self, idx: usize, cfg: ClientConfig) {
        let random = self.rng.next_u64();
        let server = self.server_addr();
        let now = self.now;
        if let Some(p) = self.peers.get_mut(idx) {
            p.client = Client::new(cfg).expect("valid client config");
            p.client.connect(server, random, now);
        }
    }

    /// Hand a datagram to the server as if it came from `from` (an attacker or a replay).
    /// Отдать датаграмму серверу, как будто она пришла с `from`.
    pub fn inject(&mut self, from: &Addr, bytes: &[u8]) {
        self.server.handle_datagram(from, bytes, self.now);
    }

    fn route_server_output(&mut self) {
        let mut buf = [0u8; 1500];
        let mut left = self.server_budget.unwrap_or(usize::MAX);
        while left > 0 {
            let Some((to, n)) = self.server.poll_transmit(&mut buf, self.now) else {
                break;
            };
            left -= 1;
            let data = buf.get(..n).unwrap_or(&[]);
            match self.peers.iter_mut().find(|p| p.addr == to) {
                Some(p) => p.down.send(self.now, data),
                None => self.stray.push((to, data.to_vec())),
            }
        }
    }

    /// Advance by one tick. / Шаг на один такт.
    pub fn step(&mut self) {
        self.now += self.tick_us;
        let now = self.now;

        // arrivals
        for i in 0..self.peers.len() {
            let addr = match self.peers.get(i) {
                Some(p) => p.addr,
                None => continue,
            };
            while let Some(d) = self.peers.get_mut(i).and_then(|p| p.up.poll(now)) {
                self.server.handle_datagram(&addr, &d, now);
            }
            let server = self.server_addr();
            if let Some(p) = self.peers.get_mut(i) {
                while let Some(d) = p.down.poll(now) {
                    p.client.handle_datagram(&server, &d, now);
                }
            }
        }

        // host duties for the server
        if now >= self.next_rotation {
            let mut fresh = [0u8; 16];
            fresh[..8].copy_from_slice(&self.rng.next_u64().to_le_bytes());
            fresh[8..].copy_from_slice(&self.rng.next_u64().to_le_bytes());
            self.server.rotate_secret(fresh, now);
            self.next_rotation = now + self.rotation_us;
        }
        // a host calls this every loop iteration; it does nothing unless something is due
        self.server.handle_timeout(now);
        self.route_server_output();
        if self.drain_events {
            while let Some(e) = self.server.poll_event() {
                self.server_events.push(e);
            }
        }

        // clients
        let mut buf = [0u8; 1500];
        for p in &mut self.peers {
            while let Some((_, n)) = p.client.poll_transmit(&mut buf, now) {
                p.up.send(now, buf.get(..n).unwrap_or(&[]));
            }
            while let Some(e) = p.client.poll_event() {
                p.events.push(e);
            }
        }
    }

    /// Run for `us` microseconds of virtual time. / Прогнать `us` микросекунд виртуального времени.
    pub fn run_for(&mut self, us: u64) {
        let end = self.now + us;
        while self.now < end {
            self.step();
        }
    }

    /// Run until `done` is true or `limit_us` has passed; returns whether `done` held.
    /// Гнать, пока `done` не станет истиной или не пройдёт `limit_us`.
    pub fn run_until(&mut self, limit_us: u64, mut done: impl FnMut(&mut Self) -> bool) -> bool {
        let end = self.now + limit_us;
        while self.now < end {
            if done(self) {
                return true;
            }
            self.step();
        }
        done(self)
    }

    /// Hash of everything that crossed every link. / Хеш всего, что прошло по всем каналам.
    pub fn trace(&self) -> u64 {
        let mut h = TraceHash::default();
        for p in &self.peers {
            h.u64(p.up.trace());
            h.u64(p.down.trace());
        }
        h.value()
    }

    /// Whether client `i` is connected from its own point of view. / Подключён ли клиент `i`.
    pub fn client_connected(&self, i: usize) -> bool {
        self.peers.get(i).is_some_and(|p| p.client.is_connected())
    }

    /// Number of `Connected` events the server has produced. / Сколько событий `Connected`.
    pub fn connected_events(&self) -> usize {
        self.server_events
            .iter()
            .filter(|e| matches!(e, Event::Connected { .. }))
            .count()
    }
}
