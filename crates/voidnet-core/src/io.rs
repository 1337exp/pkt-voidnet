//! Bounds-checked byte reader and writer used by the wire code.
//! Читатель и писатель байтов с проверкой границ.

use crate::varint;
use crate::wire::{ParseError, WriteError};

/// Cursor over an input slice. Never indexes, every read checks the bounds.
/// Курсор по входному срезу. Не индексирует, каждое чтение проверяет границы.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let end = self.pos.checked_add(n).ok_or(ParseError::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(ParseError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let s = self.buf.get(self.pos..).unwrap_or(&[]);
        self.pos = self.buf.len();
        s
    }

    pub fn u8(&mut self) -> Result<u8, ParseError> {
        let b = self.bytes(1)?;
        b.first().copied().ok_or(ParseError::Truncated)
    }

    pub fn u16(&mut self) -> Result<u16, ParseError> {
        let b: [u8; 2] = self
            .bytes(2)?
            .try_into()
            .map_err(|_| ParseError::Truncated)?;
        Ok(u16::from_le_bytes(b))
    }

    pub fn u32(&mut self) -> Result<u32, ParseError> {
        let b: [u8; 4] = self
            .bytes(4)?
            .try_into()
            .map_err(|_| ParseError::Truncated)?;
        Ok(u32::from_le_bytes(b))
    }

    pub fn u64(&mut self) -> Result<u64, ParseError> {
        let b: [u8; 8] = self
            .bytes(8)?
            .try_into()
            .map_err(|_| ParseError::Truncated)?;
        Ok(u64::from_le_bytes(b))
    }

    pub fn varint(&mut self) -> Result<u32, ParseError> {
        let tail = self.buf.get(self.pos..).ok_or(ParseError::Truncated)?;
        let (v, n) = varint::decode(tail).ok_or(ParseError::Noncanonical)?;
        self.pos += n;
        Ok(v)
    }

    /// All remaining bytes must be zero (handshake padding).
    /// Все оставшиеся байты должны быть нулями (дополнение рукопожатия).
    pub fn zero_padding(&mut self) -> Result<(), ParseError> {
        if self.rest().iter().all(|&b| b == 0) {
            Ok(())
        } else {
            Err(ParseError::NonZeroPadding)
        }
    }
}

/// Cursor over an output slice. A failed write leaves the position unchanged.
/// Курсор по выходному срезу. Неудачная запись не сдвигает позицию.
pub struct Writer<'b> {
    buf: &'b mut [u8],
    pos: usize,
}

impl<'b> Writer<'b> {
    /// `limit` caps the usable length (for example the datagram size limit).
    pub fn new(buf: &'b mut [u8], limit: usize) -> Self {
        let n = buf.len().min(limit);
        let buf = buf.get_mut(..n).unwrap_or_default();
        Self { buf, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn put(&mut self, data: &[u8]) -> Result<(), WriteError> {
        let end = self
            .pos
            .checked_add(data.len())
            .ok_or(WriteError::NoSpace)?;
        let dst = self.buf.get_mut(self.pos..end).ok_or(WriteError::NoSpace)?;
        dst.copy_from_slice(data);
        self.pos = end;
        Ok(())
    }

    pub fn put_u8(&mut self, v: u8) -> Result<(), WriteError> {
        self.put(&[v])
    }

    pub fn put_u16(&mut self, v: u16) -> Result<(), WriteError> {
        self.put(&v.to_le_bytes())
    }

    pub fn put_u32(&mut self, v: u32) -> Result<(), WriteError> {
        self.put(&v.to_le_bytes())
    }

    pub fn put_u64(&mut self, v: u64) -> Result<(), WriteError> {
        self.put(&v.to_le_bytes())
    }

    pub fn put_varint(&mut self, v: u32) -> Result<(), WriteError> {
        let tail = self.buf.get_mut(self.pos..).ok_or(WriteError::NoSpace)?;
        let n = varint::encode(v, tail).ok_or(WriteError::NoSpace)?;
        self.pos += n;
        Ok(())
    }

    pub fn put_zeros(&mut self, n: usize) -> Result<(), WriteError> {
        let end = self.pos.checked_add(n).ok_or(WriteError::NoSpace)?;
        let dst = self.buf.get_mut(self.pos..end).ok_or(WriteError::NoSpace)?;
        dst.fill(0);
        self.pos = end;
        Ok(())
    }

    /// Run `f`; if it fails, restore the position.
    /// Выполнить `f`; при ошибке вернуть позицию назад.
    pub fn atomic<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, WriteError>,
    ) -> Result<T, WriteError> {
        let start = self.pos;
        let r = f(self);
        if r.is_err() {
            self.pos = start;
        }
        r
    }
}
