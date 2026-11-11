//! Canonical unsigned LEB128 limited to `u32` (1-5 bytes). See `docs/wire.md`, section 0.
//! Каноничный беззнаковый LEB128, ограниченный `u32` (1-5 байт).

/// Longest encoding. / Самая длинная запись.
pub const MAX_LEN: usize = 5;

/// Encoded length of `v`. / Длина записи `v`.
pub const fn len(v: u32) -> usize {
    match v {
        0..=0x7F => 1,
        0x80..=0x3FFF => 2,
        0x4000..=0x1F_FFFF => 3,
        0x20_0000..=0x0FFF_FFFF => 4,
        _ => 5,
    }
}

/// Write `v` at the start of `out`; `None` if `out` is too short.
/// Записать `v` в начало `out`; `None`, если места мало.
pub fn encode(v: u32, out: &mut [u8]) -> Option<usize> {
    let n = len(v);
    let mut v = v;
    for i in 0..n {
        let mut b = (v & 0x7F) as u8;
        v >>= 7;
        if i + 1 < n {
            b |= 0x80;
        }
        *out.get_mut(i)? = b;
    }
    Some(n)
}

/// Read a canonical varint from the start of `inp`: `(value, bytes used)`.
/// `None` for truncated, non-canonical (trailing zero group) or over-`u32` input.
/// Прочитать каноничный varint: `(значение, прочитано байт)`. `None` для обрыва,
/// неминимальной записи или значения больше `u32`.
pub fn decode(inp: &[u8]) -> Option<(u32, usize)> {
    let mut v: u32 = 0;
    for i in 0..MAX_LEN {
        let b = *inp.get(i)?;
        if i == MAX_LEN - 1 && b > 0x0F {
            return None;
        }
        v |= u32::from(b & 0x7F) << (7 * i);
        if b & 0x80 == 0 {
            if i > 0 && b == 0 {
                return None;
            }
            return Some((v, i + 1));
        }
    }
    None
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
    fn roundtrip_boundaries() {
        for v in [
            0u32,
            1,
            0x7F,
            0x80,
            0x3FFF,
            0x4000,
            0x1F_FFFF,
            0x20_0000,
            0x0FFF_FFFF,
            0x1000_0000,
            u32::MAX,
        ] {
            let mut buf = [0u8; MAX_LEN];
            let n = encode(v, &mut buf).unwrap();
            assert_eq!(n, len(v), "len({v})");
            assert_eq!(decode(&buf[..n]), Some((v, n)), "value {v}");
        }
    }

    #[test]
    fn rejects_non_canonical() {
        assert_eq!(decode(&[0x80, 0x00]), None);
        assert_eq!(decode(&[0xFF, 0x80, 0x00]), None);
        assert_eq!(decode(&[0x00]), Some((0, 1)));
    }

    #[test]
    fn rejects_overflow_and_truncation() {
        assert_eq!(decode(&[0xFF, 0xFF, 0xFF, 0xFF, 0x10]), None);
        assert_eq!(decode(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]), Some((u32::MAX, 5)));
        assert_eq!(decode(&[0xFF, 0xFF, 0xFF, 0xFF, 0x8F]), None);
        assert_eq!(decode(&[0x80]), None);
        assert_eq!(decode(&[]), None);
    }

    #[test]
    fn encode_into_short_buffer_fails() {
        let mut buf = [0u8; 1];
        assert_eq!(encode(200, &mut buf), None);
    }
}
