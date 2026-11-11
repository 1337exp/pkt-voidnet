//! SipHash-1-3, 64-bit output, and a constant-time comparison.
//! Checked against the Zig standard library (`std.crypto.auth.siphash.SipHash64(1, 3)`).
//! SipHash-1-3 с 64-битным выводом и сравнение за постоянное время. Сверен со стандартной
//! библиотекой Zig.

/// Keyed hash of `data`. / Хеш `data` с ключом.
pub fn siphash13(key: &[u8; 16], data: &[u8]) -> u64 {
    let (k0, k1) = split_key(key);
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    let (blocks, rest) = data.as_chunks::<8>();
    for c in blocks {
        let m = u64::from_le_bytes(*c);
        v[3] ^= m;
        round(&mut v);
        v[0] ^= m;
    }
    let mut last = (data.len() as u64) << 56;
    for (i, &b) in rest.iter().enumerate() {
        last |= u64::from(b) << (8 * i);
    }
    v[3] ^= last;
    round(&mut v);
    v[0] ^= last;
    v[2] ^= 0xff;
    round(&mut v);
    round(&mut v);
    round(&mut v);
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

fn le_u64(c: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    for (d, s) in b.iter_mut().zip(c) {
        *d = *s;
    }
    u64::from_le_bytes(b)
}

fn split_key(key: &[u8; 16]) -> (u64, u64) {
    let (a, b) = key.split_at(8);
    (le_u64(a), le_u64(b))
}

fn round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
}

/// Equality without an early exit on the first differing bit.
/// Сравнение без раннего выхода по первому различию.
pub fn ct_eq_u64(a: u64, b: u64) -> bool {
    let d = core::hint::black_box(a ^ b);
    (d | d.wrapping_neg()) >> 63 == 0
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
    fn matches_zig_std_reference() {
        // key = 00 01 .. 0f, data[i] = (i * 7 + 3) & 0xff; values from Zig 0.17 std.crypto
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let data: [u8; 70] = core::array::from_fn(|i| ((i * 7 + 3) & 0xff) as u8);
        let want = [
            (0usize, 0xabac_0158_050f_c4dcu64),
            (1, 0x2f28_48bd_f070_e448),
            (7, 0xc2b1_c4ef_b962_bfb6),
            (8, 0x5e53_2924_8666_2ee6),
            (9, 0x268e_415a_de4e_09d2),
            (15, 0x57c2_a248_9d64_ff8f),
            (16, 0x4a03_ed90_335c_4783),
            (17, 0xaf0a_14aa_9c49_df04),
            (31, 0x3e54_e37d_dfda_3a0f),
            (55, 0x6b83_2f96_6f51_2910),
            (64, 0xbd84_19e8_0635_ccbe),
            (70, 0x7670_c79b_5083_a0a7),
        ];
        for (n, h) in want {
            assert_eq!(siphash13(&key, &data[..n]), h, "len {n}");
        }
    }

    #[test]
    fn ct_eq() {
        assert!(ct_eq_u64(5, 5));
        assert!(!ct_eq_u64(5, 6));
        assert!(!ct_eq_u64(0, 1 << 63));
        assert!(ct_eq_u64(u64::MAX, u64::MAX));
    }
}
