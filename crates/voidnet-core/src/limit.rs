//! Token buckets for pre-authentication admission control. Fixed memory, no allocation.
//! Корзины токенов для допуска до проверки подлинности. Фиксированная память.

/// One bucket. A token costs one request; `rate_per_s == 0` disables limiting.
/// Одна корзина. Запрос стоит один токен; `rate_per_s == 0` отключает лимит.
#[derive(Clone, Copy, Debug, Default)]
pub struct Bucket {
    tokens_milli: u64,
    updated_us: u64,
    primed: bool,
}

impl Bucket {
    pub fn allow(&mut self, now_us: u64, rate_per_s: u32, burst: u32) -> bool {
        if rate_per_s == 0 {
            return true;
        }
        let cap = u64::from(burst).saturating_mul(1000);
        if !self.primed {
            self.primed = true;
            self.tokens_milli = cap;
            self.updated_us = now_us;
        }
        let elapsed = now_us.saturating_sub(self.updated_us);
        // microseconds * (tokens/s) / 1000 = milli-tokens
        let refill = elapsed.saturating_mul(u64::from(rate_per_s)) / 1000;
        self.tokens_milli = self.tokens_milli.saturating_add(refill).min(cap);
        self.updated_us = self.updated_us.max(now_us);
        if self.tokens_milli < 1000 {
            return false;
        }
        self.tokens_milli -= 1000;
        true
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Entry {
    used: bool,
    key: u64,
    bucket: Bucket,
}

/// Per-source buckets in a fixed table. When the table is full the stalest entry is
/// replaced, so memory never grows.
/// Корзины по источникам в таблице фиксированного размера; при переполнении вытесняется
/// самая давняя запись.
#[derive(Clone, Debug)]
pub struct RateTable<const R: usize> {
    entries: [Entry; R],
}

impl<const R: usize> Default for RateTable<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const R: usize> RateTable<R> {
    pub fn new() -> Self {
        Self {
            entries: [Entry::default(); R],
        }
    }

    pub fn allow(&mut self, key: u64, now_us: u64, rate_per_s: u32, burst: u32) -> bool {
        if rate_per_s == 0 {
            return true;
        }
        let idx = self.find_or_replace(key);
        match self.entries.get_mut(idx) {
            Some(e) => {
                if !e.used || e.key != key {
                    *e = Entry {
                        used: true,
                        key,
                        bucket: Bucket::default(),
                    };
                }
                e.bucket.allow(now_us, rate_per_s, burst)
            }
            None => false,
        }
    }

    fn find_or_replace(&self, key: u64) -> usize {
        let mut stalest = 0usize;
        let mut stalest_at = u64::MAX;
        for (i, e) in self.entries.iter().enumerate() {
            if !e.used || e.key == key {
                return i;
            }
            if e.bucket.updated_us < stalest_at {
                stalest_at = e.bucket.updated_us;
                stalest = i;
            }
        }
        stalest
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refill() {
        let mut b = Bucket::default();
        // rate 2/s, burst 2
        assert!(b.allow(0, 2, 2));
        assert!(b.allow(0, 2, 2));
        assert!(!b.allow(0, 2, 2));
        assert!(!b.allow(400_000, 2, 2)); // 0.8 token
        assert!(b.allow(500_000, 2, 2)); // 1.0 token
        assert!(!b.allow(500_000, 2, 2));
        assert!(b.allow(10_000_000, 2, 2)); // long idle refills to the burst only
        assert!(b.allow(10_000_000, 2, 2));
        assert!(!b.allow(10_000_000, 2, 2));
    }

    #[test]
    fn disabled_when_rate_is_zero() {
        let mut b = Bucket::default();
        for _ in 0..1000 {
            assert!(b.allow(0, 0, 1));
        }
    }

    #[test]
    fn sources_are_isolated() {
        let mut t: RateTable<4> = RateTable::new();
        assert!(t.allow(1, 0, 2, 2) && t.allow(1, 0, 2, 2));
        assert!(!t.allow(1, 0, 2, 2));
        assert!(t.allow(2, 0, 2, 2), "another source has its own bucket");
    }

    #[test]
    fn full_table_replaces_the_stalest_entry() {
        let mut t: RateTable<2> = RateTable::new();
        assert!(t.allow(1, 100, 1, 1));
        assert!(t.allow(2, 200, 1, 1));
        assert!(t.allow(3, 300, 1, 1)); // evicts key 1, the stalest
        assert!(!t.allow(2, 300, 1, 1), "key 2 kept its (empty) bucket");
        assert!(t.allow(1, 300, 1, 1), "key 1 was evicted and starts fresh");
    }

    #[test]
    fn time_going_backwards_is_harmless() {
        let mut b = Bucket::default();
        assert!(b.allow(1_000_000, 1, 1));
        assert!(!b.allow(500_000, 1, 1));
        assert!(b.allow(2_100_000, 1, 1));
    }
}
