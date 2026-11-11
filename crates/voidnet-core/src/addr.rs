//! Opaque peer address. The host defines the bytes; the core only compares and hashes them.
//! Непрозрачный адрес пира. Байты задаёт хозяин; ядро их только сравнивает и хеширует.

/// Longest address in bytes. / Наибольшая длина адреса.
pub const ADDR_MAX: usize = 20;

/// A peer address of at most [`ADDR_MAX`] bytes. The first `source_len` bytes name the
/// *source* (typically the IP without the port) and are what per-source limits count; all
/// bytes name the endpoint. Recommended form: 16 bytes IPv6 or IPv4-mapped, then 2 bytes
/// of port, with `source_len` = 16.
///
/// Адрес пира не длиннее [`ADDR_MAX`] байт. Первые `source_len` байт называют *источник*
/// (обычно IP без порта), по ним считаются лимиты; все байты называют конечную точку.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Addr {
    len: u8,
    source_len: u8,
    bytes: [u8; ADDR_MAX],
}

impl Addr {
    /// `None` if `bytes` is empty, longer than [`ADDR_MAX`], or `source_len` is not in
    /// `1..=bytes.len()`. / `None` при пустых, слишком длинных байтах или неверном `source_len`.
    pub fn new(bytes: &[u8], source_len: usize) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > ADDR_MAX || source_len == 0 || source_len > bytes.len()
        {
            return None;
        }
        let mut a = Self {
            len: u8::try_from(bytes.len()).ok()?,
            source_len: u8::try_from(source_len).ok()?,
            bytes: [0; ADDR_MAX],
        };
        for (d, s) in a.bytes.iter_mut().zip(bytes) {
            *d = *s;
        }
        Some(a)
    }

    /// An IPv4 endpoint in the recommended 18-byte form. / IPv4-конечная точка (18 байт).
    pub fn from_ipv4(ip: [u8; 4], port: u16) -> Self {
        let mut b = [0u8; 18];
        b[10] = 0xFF;
        b[11] = 0xFF;
        b[12..16].copy_from_slice(&ip);
        b[16..18].copy_from_slice(&port.to_be_bytes());
        // 18 bytes and source_len 16 are always valid
        Self {
            len: 18,
            source_len: 16,
            bytes: {
                let mut full = [0u8; ADDR_MAX];
                full[..18].copy_from_slice(&b);
                full
            },
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// The bytes that identify the source for limits. / Байты источника для лимитов.
    pub fn source(&self) -> &[u8] {
        self.bytes
            .get(..usize::from(self.source_len))
            .unwrap_or(&[])
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
    fn validation() {
        assert!(Addr::new(&[], 1).is_none());
        assert!(Addr::new(&[1; 21], 1).is_none());
        assert!(Addr::new(&[1; 4], 0).is_none());
        assert!(Addr::new(&[1; 4], 5).is_none());
        assert!(Addr::new(&[1; 20], 16).is_some());
    }

    #[test]
    fn equality_ignores_padding_and_distinguishes_ports() {
        let a = Addr::from_ipv4([1, 2, 3, 4], 100);
        let b = Addr::from_ipv4([1, 2, 3, 4], 100);
        let c = Addr::from_ipv4([1, 2, 3, 4], 101);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.source(), c.source());
        assert_eq!(a.as_bytes().len(), 18);
    }
}
