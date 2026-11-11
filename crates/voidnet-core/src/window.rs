//! Packet number reconstruction and the receive window. See `docs/wire.md`, 2.1 and 2.2.
//! Восстановление номера пакета и окно приёма.

/// Window size in packet numbers. / Размер окна в номерах пакетов.
pub const RECV_WINDOW: u64 = 256;

const WORDS: usize = (RECV_WINDOW / 64) as usize;

/// What the window says about a packet number. / Что окно говорит о номере.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    /// Not seen, inside or ahead of the window. / Не встречался.
    New,
    /// Already received. / Уже принят.
    Duplicate,
    /// Below the window. / Ниже окна.
    TooOld,
}

/// Bitmap of the most recent [`RECV_WINDOW`] packet numbers: bit `i` of the window
/// means packet `largest - i` was received.
/// Битовая карта последних [`RECV_WINDOW`] номеров: бит `i` значит «принят номер `largest - i`».
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RecvWindow {
    largest: u64,
    any: bool,
    bits: [u64; WORDS],
}

impl RecvWindow {
    pub const fn new() -> Self {
        Self {
            largest: 0,
            any: false,
            bits: [0; WORDS],
        }
    }

    /// Largest packet number received, if any. / Наибольший принятый номер.
    pub fn largest(&self) -> Option<u64> {
        self.any.then_some(self.largest)
    }

    fn word(&self, i: usize) -> u64 {
        self.bits.get(i).copied().unwrap_or(0)
    }

    /// Full packet number from its low 16 bits, or `None` if it would be negative.
    /// Полный номер по младшим 16 битам; `None`, если вышел бы отрицательным.
    pub fn reconstruct(&self, pn16: u16) -> Option<u64> {
        let expected = if self.any {
            self.largest.saturating_add(1)
        } else {
            0
        };
        let win: u64 = 1 << 16;
        let half = win / 2;
        let candidate = (expected & !(win - 1)) | u64::from(pn16);
        if candidate.saturating_add(half) <= expected {
            candidate.checked_add(win)
        } else if candidate > expected.saturating_add(half) {
            candidate.checked_sub(win)
        } else {
            Some(candidate)
        }
    }

    /// Whether `pn` is a duplicate, too old, or new. Does not change the window.
    /// Дубликат, слишком старый или новый. Окно не меняет.
    pub fn classify(&self, pn: u64) -> Class {
        if !self.any || pn > self.largest {
            return Class::New;
        }
        let d = self.largest - pn;
        if d >= RECV_WINDOW {
            return Class::TooOld;
        }
        if self.bit(d) {
            Class::Duplicate
        } else {
            Class::New
        }
    }

    fn bit(&self, d: u64) -> bool {
        let w = self.word((d / 64) as usize);
        (w >> (d % 64)) & 1 == 1
    }

    /// Whether packet `pn` is recorded as received (false below the window).
    /// Записан ли `pn` как принятый (ниже окна всегда false).
    pub fn contains(&self, pn: u64) -> bool {
        self.any
            && pn <= self.largest
            && self.largest - pn < RECV_WINDOW
            && self.bit(self.largest - pn)
    }

    /// Record `pn` as received. Call only after the datagram is authenticated.
    /// Returns what [`classify`](Self::classify) would have said before the call.
    /// Записать `pn` как принятый. Вызывать только после проверки подлинности.
    pub fn mark(&mut self, pn: u64) -> Class {
        let class = self.classify(pn);
        if class != Class::New {
            return class;
        }
        if !self.any {
            self.any = true;
            self.largest = pn;
            self.bits = core::array::from_fn(|i| u64::from(i == 0));
            return class;
        }
        if pn > self.largest {
            self.shift(pn - self.largest);
            self.largest = pn;
            self.bits = core::array::from_fn(|i| {
                if i == 0 {
                    self.word(0) | 1
                } else {
                    self.word(i)
                }
            });
        } else {
            let d = self.largest - pn;
            let (wi, mask) = ((d / 64) as usize, 1u64 << (d % 64));
            self.bits = core::array::from_fn(|i| {
                if i == wi {
                    self.word(i) | mask
                } else {
                    self.word(i)
                }
            });
        }
        class
    }

    /// Move every bit `n` places towards "older".
    fn shift(&mut self, n: u64) {
        if n >= RECV_WINDOW {
            self.bits = [0; WORDS];
            return;
        }
        let ws = (n / 64) as usize;
        let bs = (n % 64) as u32;
        self.bits = core::array::from_fn(|i| {
            if i < ws {
                return 0;
            }
            let lo = self.word(i - ws).checked_shl(bs).unwrap_or(0);
            let carry = if bs > 0 && i > ws {
                self.word(i - ws - 1) >> (64 - bs)
            } else {
                0
            };
            lo | carry
        });
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
    fn reconstruct_from_empty() {
        let w = RecvWindow::new();
        assert_eq!(w.reconstruct(0), Some(0));
        assert_eq!(w.reconstruct(5), Some(5));
        assert_eq!(w.reconstruct(0x7FFF), Some(0x7FFF));
        // expected 0, interval (-32768, 32768]: 0x8000 is the upper edge, still valid
        assert_eq!(w.reconstruct(0x8000), Some(0x8000));
        // would be negative: dropped
        assert_eq!(w.reconstruct(0x8001), None);
        assert_eq!(w.reconstruct(0xFFFF), None);
    }

    #[test]
    fn reconstruct_across_wrap() {
        let mut w = RecvWindow::new();
        w.mark(65_530);
        // expected 65531
        assert_eq!(w.reconstruct(65_531), Some(65_531));
        assert_eq!(w.reconstruct(2), Some(65_538));
        assert_eq!(w.reconstruct(65_520), Some(65_520));
        let mut w = RecvWindow::new();
        w.mark(0x3_0005);
        assert_eq!(w.reconstruct(0x0004), Some(0x3_0004));
        assert_eq!(w.reconstruct(0xFFFF), Some(0x2_FFFF));
        assert_eq!(w.reconstruct(0x0010), Some(0x3_0010));
    }

    #[test]
    fn reconstruct_interval_edges() {
        let mut w = RecvWindow::new();
        w.mark(99_999); // expected 100_000
        let e: u64 = 100_000;
        // exactly 2^15 above: stays; exactly 2^15 below: goes up to 2^15 above
        assert_eq!(
            w.reconstruct(((e + 32_768) & 0xFFFF) as u16),
            Some(e + 32_768)
        );
        assert_eq!(
            w.reconstruct(((e - 32_768) & 0xFFFF) as u16),
            Some(e + 32_768)
        );
        assert_eq!(
            w.reconstruct(((e - 32_767) & 0xFFFF) as u16),
            Some(e - 32_767)
        );
        assert_eq!(
            w.reconstruct(((e + 32_769) & 0xFFFF) as u16),
            Some(e - 32_767)
        );
    }

    #[test]
    fn duplicates_and_too_old() {
        let mut w = RecvWindow::new();
        assert_eq!(w.mark(1000), Class::New);
        assert_eq!(w.mark(1000), Class::Duplicate);
        assert_eq!(w.mark(990), Class::New);
        assert_eq!(w.mark(990), Class::Duplicate);
        assert_eq!(w.mark(1000 - 255), Class::New);
        assert_eq!(w.classify(1000 - 256), Class::TooOld);
        assert_eq!(w.mark(1000 - 256), Class::TooOld);
        assert!(w.contains(1000) && w.contains(990) && !w.contains(991));
    }

    #[test]
    fn shift_keeps_history_and_drops_old() {
        let mut w = RecvWindow::new();
        for pn in [10u64, 11, 14] {
            w.mark(pn);
        }
        w.mark(14 + 70);
        for pn in [10u64, 11, 14, 84] {
            assert!(w.contains(pn), "{pn}");
        }
        assert!(!w.contains(12) && !w.contains(13));
        w.mark(84 + 300);
        assert!(w.contains(384));
        assert!(!w.contains(84));
        assert_eq!(w.classify(84), Class::TooOld);
    }

    #[test]
    fn matches_reference_model_on_pseudo_random_input() {
        // xorshift, deterministic; reference: a plain list of received numbers
        let mut x: u64 = 0x1234_5678_9ABC_DEF1;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut w = RecvWindow::new();
        let mut seen = std::vec::Vec::new();
        let mut largest: u64 = 0;
        for _ in 0..20_000 {
            let r = next();
            let pn = if r % 4 == 0 && largest > 5 {
                largest.saturating_sub((r >> 8) % 300)
            } else {
                largest + (r >> 8) % 4
            };
            let expect_old =
                largest.saturating_sub(pn) >= RECV_WINDOW && !seen.is_empty() && pn < largest;
            let was_seen = seen.contains(&pn);
            let class = w.mark(pn);
            if expect_old {
                assert_eq!(class, Class::TooOld);
            } else if was_seen {
                assert_eq!(class, Class::Duplicate);
            } else {
                assert_eq!(class, Class::New);
                seen.push(pn);
            }
            largest = largest.max(pn);
            assert_eq!(w.largest(), Some(largest));
        }
        for pn in largest.saturating_sub(RECV_WINDOW - 1)..=largest {
            assert_eq!(w.contains(pn), seen.contains(&pn), "pn {pn}");
        }
    }
}
