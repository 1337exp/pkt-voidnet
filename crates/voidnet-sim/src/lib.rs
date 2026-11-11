//! Deterministic network simulator: virtual clock, own PRNG, a lossy link.
//! The same seed gives the same run on every OS: the PRNG is implemented here on purpose,
//! because crates such as `rand` change algorithms between versions.
//!
//! Детерминированный имитатор сети: виртуальные часы, собственный ГСЧ, канал с потерями.
//! Одно зерно даёт один и тот же прогон на любой ОС: ГСЧ написан здесь намеренно, потому
//! что готовые крейты (`rand`) меняют алгоритмы между версиями.

pub mod pair;
pub mod world;

/// PCG-XSH-RR 32 (O'Neill). 64-bit state, 32-bit output.
/// PCG-XSH-RR 32: состояние 64 бита, вывод 32 бита.
#[derive(Clone, Debug)]
pub struct Pcg32 {
    state: u64,
    inc: u64,
}

impl Pcg32 {
    pub fn new(seed: u64, stream: u64) -> Self {
        let mut r = Self {
            state: 0,
            inc: (stream << 1) | 1,
        };
        r.next_u32();
        r.state = r.state.wrapping_add(seed);
        r.next_u32();
        r
    }

    pub fn next_u32(&mut self) -> u32 {
        let old = self.state;
        self.state = old
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(self.inc);
        let xorshifted = (((old >> 18) ^ old) >> 27) as u32;
        let rot = (old >> 59) as u32;
        xorshifted.rotate_right(rot)
    }

    pub fn next_u64(&mut self) -> u64 {
        (u64::from(self.next_u32()) << 32) | u64::from(self.next_u32())
    }

    /// Uniform in `0..n` (`n > 0`), unbiased by rejection. / Равномерно в `0..n`.
    pub fn below(&mut self, n: u32) -> u32 {
        assert!(n > 0);
        let threshold = n.wrapping_neg() % n;
        loop {
            let r = self.next_u32();
            if r >= threshold {
                return r % n;
            }
        }
    }

    /// True with probability `permille / 1000`. / Истина с вероятностью `permille / 1000`.
    pub fn chance(&mut self, permille: u32) -> bool {
        permille > 0 && self.below(1000) < permille
    }
}

/// FNV-1a 64, used to hash a run into one number (the "golden trace").
/// FNV-1a 64: хеш всего прогона в одно число («эталонная трасса»).
#[derive(Clone, Copy, Debug)]
pub struct TraceHash(u64);

impl Default for TraceHash {
    fn default() -> Self {
        Self(0xCBF2_9CE4_8422_2325)
    }
}

impl TraceHash {
    pub fn bytes(&mut self, data: &[u8]) {
        for &b in data {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01B3);
        }
    }

    pub fn u64(&mut self, v: u64) {
        self.bytes(&v.to_le_bytes());
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

/// Link impairments. All times are microseconds. / Искажения канала, время в микросекундах.
#[derive(Clone, Debug)]
pub struct Params {
    pub latency_us: u64,
    pub jitter_us: u64,
    pub loss_permille: u32,
    pub dup_permille: u32,
    pub reorder_permille: u32,
    /// Extra delay added to a reordered datagram, so later ones overtake it.
    pub reorder_delay_us: u64,
    pub max_datagram: usize,
    /// Everything sent in `[start, end)` is lost. / Всё отправленное в `[start, end)` теряется.
    pub blackout: Option<(u64, u64)>,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            latency_us: 20_000,
            jitter_us: 0,
            loss_permille: 0,
            dup_permille: 0,
            reorder_permille: 0,
            reorder_delay_us: 0,
            max_datagram: 1400,
            blackout: None,
        }
    }
}

/// Counters of what the link did. / Счётчики того, что сделал канал.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub sent: u64,
    pub delivered: u64,
    pub lost: u64,
    pub duplicated: u64,
    pub reordered: u64,
    pub oversize: u64,
    pub blackout: u64,
}

struct Pending {
    at: u64,
    seq: u64,
    data: Vec<u8>,
}

/// One direction of a simulated path. / Одно направление имитируемого пути.
pub struct Link {
    params: Params,
    rng: Pcg32,
    queue: Vec<Pending>,
    seq: u64,
    pub stats: Stats,
    trace: TraceHash,
}

impl Link {
    pub fn new(params: Params, seed: u64) -> Self {
        Self {
            params,
            rng: Pcg32::new(seed, 54),
            queue: Vec::new(),
            seq: 0,
            stats: Stats::default(),
            trace: TraceHash::default(),
        }
    }

    pub fn params_mut(&mut self) -> &mut Params {
        &mut self.params
    }

    /// Hash of every send and delivery so far. / Хеш всех отправок и доставок.
    pub fn trace(&self) -> u64 {
        self.trace.value()
    }

    fn delay(&mut self) -> u64 {
        let jitter = if self.params.jitter_us > 0 {
            self.rng.next_u64() % (self.params.jitter_us + 1)
        } else {
            0
        };
        self.params.latency_us + jitter
    }

    fn push(&mut self, at: u64, data: Vec<u8>) {
        self.seq += 1;
        self.queue.push(Pending {
            at,
            seq: self.seq,
            data,
        });
    }

    /// Hand a datagram to the link at time `now`. / Передать датаграмму каналу.
    pub fn send(&mut self, now: u64, data: &[u8]) {
        self.stats.sent += 1;
        self.trace.u64(now);
        self.trace.bytes(data);
        if data.len() > self.params.max_datagram {
            self.stats.oversize += 1;
            return;
        }
        if let Some((a, b)) = self.params.blackout {
            if now >= a && now < b {
                self.stats.blackout += 1;
                return;
            }
        }
        if self.rng.chance(self.params.loss_permille) {
            self.stats.lost += 1;
            return;
        }
        let mut at = now + self.delay();
        if self.rng.chance(self.params.reorder_permille) {
            self.stats.reordered += 1;
            at += self.params.reorder_delay_us;
        }
        self.push(at, data.to_vec());
        if self.rng.chance(self.params.dup_permille) {
            self.stats.duplicated += 1;
            let extra = self.delay();
            self.push(now + extra, data.to_vec());
        }
    }

    /// Next datagram that has arrived by `now`, in arrival order.
    /// Следующая датаграмма, дошедшая к `now`, в порядке прихода.
    pub fn poll(&mut self, now: u64) -> Option<Vec<u8>> {
        let idx = self
            .queue
            .iter()
            .enumerate()
            .filter(|(_, p)| p.at <= now)
            .min_by_key(|(_, p)| (p.at, p.seq))
            .map(|(i, _)| i)?;
        let p = self.queue.swap_remove(idx);
        self.stats.delivered += 1;
        self.trace.u64(p.at);
        self.trace.bytes(&p.data);
        Some(p.data)
    }

    /// Time of the next arrival, if any. / Время ближайшего прихода.
    pub fn next_arrival(&self) -> Option<u64> {
        self.queue.iter().map(|p| p.at).min()
    }

    pub fn in_flight(&self) -> usize {
        self.queue.len()
    }
}
