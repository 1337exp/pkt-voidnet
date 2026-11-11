//! Two established connections wired back to back through two lossy links, no handshake.
//! This isolates delivery, acknowledgements and timers (stage 3) from admission (stage 2).
//! Два установленных соединения, связанных двумя каналами с потерями, без рукопожатия.
//! Так доставка, подтверждения и таймеры (этап 3) проверяются отдельно от допуска (этап 2).

use crate::{Link, Params};
use voidnet_core::conn::{Conn, ConnConfig};
use voidnet_core::wire::{self, Datagram};
use voidnet_core::ChannelTable;

/// One end with what it has sent. / Один конец и то, что он отправил.
pub struct End {
    pub conn: Box<Conn>,
    /// Every datagram this end handed to its link, in order. / Всё, что конец отдал каналу.
    pub sent: Vec<Vec<u8>>,
}

/// The pair. / Пара.
pub struct Pair {
    pub now: u64,
    pub tick_us: u64,
    pub a: End,
    pub b: End,
    pub ab: Link,
    pub ba: Link,
    channels: ChannelTable,
}

impl Pair {
    pub fn new(cfg: ConnConfig, link: Params, seed: u64) -> Self {
        let now = 1_000_000;
        let token = 0x1357_9BDF_0246_8ACE;
        Self {
            now,
            tick_us: 1_000,
            a: End {
                conn: Box::new(Conn::new(token, cfg, now)),
                sent: Vec::new(),
            },
            b: End {
                conn: Box::new(Conn::new(token, cfg, now)),
                sent: Vec::new(),
            },
            ab: Link::new(link.clone(), seed),
            ba: Link::new(link, seed ^ 0x5A5A),
            channels: cfg.channels,
        }
    }

    fn feed(end: &mut End, link: &mut Link, channels: &ChannelTable, now: u64) {
        while let Some(d) = link.poll(now) {
            if let Ok(Datagram::Data(dd)) = wire::parse(&d, channels.as_slice()) {
                let _ = end.conn.on_datagram(&dd, now);
            }
        }
    }

    fn pump(end: &mut End, link: &mut Link, now: u64) {
        if end.conn.next_deadline().is_some_and(|t| t <= now) {
            end.conn.on_timeout(now);
        }
        let mut buf = [0u8; 1500];
        while let Some(n) = end.conn.build(now, &mut buf) {
            let d = buf.get(..n).unwrap_or(&[]);
            end.sent.push(d.to_vec());
            link.send(now, d);
        }
    }

    /// One tick. / Один такт.
    pub fn step(&mut self) {
        self.now += self.tick_us;
        let now = self.now;
        Self::feed(&mut self.b, &mut self.ab, &self.channels, now);
        Self::feed(&mut self.a, &mut self.ba, &self.channels, now);
        Self::pump(&mut self.a, &mut self.ab, now);
        Self::pump(&mut self.b, &mut self.ba, now);
    }

    pub fn run_for(&mut self, us: u64) {
        let end = self.now + us;
        while self.now < end {
            self.step();
        }
    }

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
}
