//! ACK frame: block encoding, building from a receive window, and range iteration.
//! See `docs/wire.md`, 2.3 (ACK).
//! Кадр ACK: кодирование блоков, построение из окна приёма, обход диапазонов.

use crate::io::{Reader, Writer};
use crate::window::{RecvWindow, RECV_WINDOW};
use crate::wire::{ParseError, WriteError};

/// Most blocks after the first. / Наибольшее число блоков после первого.
pub const MAX_ACK_RANGES: usize = 15;
/// Largest allowed span of one ACK frame, in packet numbers.
/// Наибольший охват одного кадра ACK в номерах пакетов.
pub const MAX_ACK_SPAN: u64 = 1 << 15;
/// One unit of the `delay` field, microseconds. / Единица поля `delay`, микросекунды.
pub const ACK_DELAY_UNIT_US: u64 = 32;

/// A decoded ACK frame. / Разобранный кадр ACK.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AckFrame {
    /// Low 16 bits of the largest acknowledged packet number.
    pub largest: u16,
    /// Hold time of `largest` in units of [`ACK_DELAY_UNIT_US`].
    pub delay: u32,
    /// Length of the first block (ends at `largest`), at least 1.
    pub first: u32,
    /// Number of `(gap, len)` blocks in use.
    pub n: u8,
    /// `(gap, len)` blocks, only the first `n` are meaningful.
    pub blocks: [(u32, u32); MAX_ACK_RANGES],
}

impl AckFrame {
    /// Read the frame body (after the tag). / Прочитать тело кадра (после тега).
    pub fn read(r: &mut Reader<'_>) -> Result<Self, ParseError> {
        let largest = r.u16()?;
        let delay = r.varint()?;
        let n = r.u8()?;
        if usize::from(n) > MAX_ACK_RANGES {
            return Err(ParseError::BadAck);
        }
        let first = r.varint()?;
        if first == 0 {
            return Err(ParseError::BadAck);
        }
        let mut span = u64::from(first);
        let mut blocks = [(0u32, 0u32); MAX_ACK_RANGES];
        for slot in blocks.iter_mut().take(usize::from(n)) {
            let gap = r.varint()?;
            let len = r.varint()?;
            if gap == 0 || len == 0 {
                return Err(ParseError::BadAck);
            }
            span += u64::from(gap) + u64::from(len);
            *slot = (gap, len);
        }
        if span > MAX_ACK_SPAN {
            return Err(ParseError::BadAck);
        }
        Ok(Self {
            largest,
            delay,
            first,
            n,
            blocks,
        })
    }

    /// Write the frame body (after the tag). / Записать тело кадра (после тега).
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), WriteError> {
        if usize::from(self.n) > MAX_ACK_RANGES || self.first == 0 {
            return Err(WriteError::Invalid);
        }
        w.put_u16(self.largest)?;
        w.put_varint(self.delay)?;
        w.put_u8(self.n)?;
        w.put_varint(self.first)?;
        for &(gap, len) in self.blocks.iter().take(usize::from(self.n)) {
            if gap == 0 || len == 0 {
                return Err(WriteError::Invalid);
            }
            w.put_varint(gap)?;
            w.put_varint(len)?;
        }
        Ok(())
    }

    /// Total span covered by the frame, in packet numbers.
    pub fn span(&self) -> u64 {
        let mut s = u64::from(self.first);
        for &(gap, len) in self.blocks.iter().take(usize::from(self.n)) {
            s += u64::from(gap) + u64::from(len);
        }
        s
    }

    /// Acknowledged ranges `(lo, hi)`, both inclusive, newest first, given the full
    /// value of `largest`. `None` if a block would reach below packet number 0.
    /// Подтверждённые диапазоны `(lo, hi)` включительно, от новых к старым.
    pub fn ranges(&self, largest_full: u64) -> Option<AckRanges> {
        if self.span() > largest_full.saturating_add(1) {
            return None;
        }
        Some(AckRanges {
            frame: *self,
            next: 0,
            hi: largest_full,
        })
    }

    /// Build a frame describing what `win` holds, newest first. `None` if nothing
    /// was received yet. Older history than 15 blocks or the window is not reported.
    /// Построить кадр по содержимому окна. `None`, если ничего не принято.
    pub fn from_window(win: &RecvWindow, delay: u32) -> Option<Self> {
        let largest = win.largest()?;
        let depth = RECV_WINDOW.min(largest + 1);
        let mut frame = Self {
            largest: (largest & 0xFFFF) as u16,
            delay,
            first: 0,
            n: 0,
            blocks: [(0, 0); MAX_ACK_RANGES],
        };
        let mut d: u64 = 0;
        // first block: the run of received numbers starting at `largest`
        while d < depth && win.contains(largest - d) {
            d += 1;
        }
        frame.first = d as u32;
        while d < depth && usize::from(frame.n) < MAX_ACK_RANGES {
            let mut gap = 0u32;
            while d < depth && !win.contains(largest - d) {
                gap += 1;
                d += 1;
            }
            if d >= depth {
                break; // the gap runs to the edge: nothing more to report
            }
            let mut len = 0u32;
            while d < depth && win.contains(largest - d) {
                len += 1;
                d += 1;
            }
            if let Some(slot) = frame.blocks.get_mut(usize::from(frame.n)) {
                *slot = (gap, len);
                frame.n += 1;
            }
        }
        Some(frame)
    }
}

/// Iterator over acknowledged `(lo, hi)` ranges. / Обход подтверждённых диапазонов.
#[derive(Clone, Copy, Debug)]
pub struct AckRanges {
    frame: AckFrame,
    /// 0 = the first block, `k` = block `k - 1` of `blocks`
    next: usize,
    /// highest packet number of the block returned next
    hi: u64,
}

impl Iterator for AckRanges {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<(u64, u64)> {
        if self.next > usize::from(self.frame.n) {
            return None;
        }
        let (hi, len) = if self.next == 0 {
            (self.hi, u64::from(self.frame.first))
        } else {
            let (gap, len) = *self.frame.blocks.get(self.next - 1)?;
            (self.hi.checked_sub(u64::from(gap))?, u64::from(len))
        };
        let lo = hi.checked_sub(len - 1)?;
        self.hi = lo.saturating_sub(1);
        self.next += 1;
        Some((lo, hi))
    }
}

/// Full value of an ACK frame's `largest`: the largest value not above `highest_sent`
/// with the given low 16 bits. `None` if there is none.
/// Полное значение `largest`: наибольшее не выше `highest_sent` с такими младшими 16 битами.
pub fn reconstruct_largest(highest_sent: u64, low16: u16) -> Option<u64> {
    let cand = (highest_sent & !0xFFFF) | u64::from(low16);
    if cand > highest_sent {
        cand.checked_sub(0x1_0000)
    } else {
        Some(cand)
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
    use std::vec::Vec;

    fn window_of(pns: &[u64]) -> RecvWindow {
        let mut w = RecvWindow::new();
        for &p in pns {
            w.mark(p);
        }
        w
    }

    fn ranges_of(f: &AckFrame, largest: u64) -> Vec<(u64, u64)> {
        f.ranges(largest).unwrap().collect()
    }

    #[test]
    fn from_window_single_run() {
        let w = window_of(&[5, 6, 7, 8]);
        let f = AckFrame::from_window(&w, 10).unwrap();
        assert_eq!((f.largest, f.first, f.n), (8, 4, 0));
        assert_eq!(ranges_of(&f, 8), [(5, 8)]);
    }

    #[test]
    fn from_window_with_gaps() {
        let w = window_of(&[1, 2, 5, 6, 7, 10]);
        let f = AckFrame::from_window(&w, 0).unwrap();
        assert_eq!(ranges_of(&f, 10), [(10, 10), (5, 7), (1, 2)]);
        assert_eq!((f.first, f.n), (1, 2));
        assert_eq!(f.blocks[0], (2, 3));
        assert_eq!(f.blocks[1], (2, 2));
    }

    #[test]
    fn from_window_empty() {
        assert!(AckFrame::from_window(&RecvWindow::new(), 0).is_none());
    }

    #[test]
    fn write_read_roundtrip() {
        let w = window_of(&[1, 2, 5, 6, 7, 10, 300, 301]);
        let f = AckFrame::from_window(&w, 625).unwrap();
        let mut buf = [0u8; 64];
        let mut wr = Writer::new(&mut buf, 64);
        f.write(&mut wr).unwrap();
        let n = wr.pos();
        let mut r = Reader::new(&buf[..n]);
        let g = AckFrame::read(&mut r).unwrap();
        assert!(r.is_empty());
        assert_eq!(
            f.ranges(301).unwrap().collect::<Vec<_>>(),
            g.ranges(301).unwrap().collect::<Vec<_>>()
        );
        assert_eq!(f.largest, g.largest);
        assert_eq!(f.delay, g.delay);
    }

    #[test]
    fn read_rejects_bad_frames() {
        // n = 16 > 15
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf, 8);
        w.put_u16(1).unwrap();
        w.put_varint(0).unwrap();
        w.put_u8(16).unwrap();
        w.put_varint(1).unwrap();
        let n = w.pos();
        assert_eq!(
            AckFrame::read(&mut Reader::new(&buf[..n])),
            Err(ParseError::BadAck)
        );
        // first = 0
        let buf = [1u8, 0, 0, 0, 0];
        assert_eq!(
            AckFrame::read(&mut Reader::new(&buf)),
            Err(ParseError::BadAck)
        );
        // gap = 0
        let buf = [1u8, 0, 0, 1, 1, 0, 1];
        assert_eq!(
            AckFrame::read(&mut Reader::new(&buf)),
            Err(ParseError::BadAck)
        );
        // span over 32768: first = 32769 as varint
        let mut big = [0u8; 8];
        let mut w = Writer::new(&mut big, 8);
        w.put_u16(1).unwrap();
        w.put_varint(0).unwrap();
        w.put_u8(0).unwrap();
        w.put_varint(32_769).unwrap();
        let n = w.pos();
        assert_eq!(
            AckFrame::read(&mut Reader::new(&big[..n])),
            Err(ParseError::BadAck)
        );
    }

    #[test]
    fn ranges_reject_reaching_below_zero() {
        let w = window_of(&[0, 1, 2]);
        let f = AckFrame::from_window(&w, 0).unwrap();
        assert!(f.ranges(2).is_some());
        assert!(f.ranges(1).is_none());
    }

    #[test]
    fn reconstruct_largest_cases() {
        assert_eq!(
            reconstruct_largest(70_000, (70_000 & 0xFFFF) as u16),
            Some(70_000)
        );
        assert_eq!(reconstruct_largest(70_000, 3), Some(65_539));
        assert_eq!(reconstruct_largest(70_000, 0xFFFF), Some(65_535));
        assert_eq!(reconstruct_largest(100, 200), None);
        assert_eq!(reconstruct_largest(65_535, 65_535), Some(65_535));
    }
}
