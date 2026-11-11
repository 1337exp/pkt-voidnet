//! A stream of 16-bit packet numbers into the receive window: no panic, a number is
//! never accepted twice, `largest` never decreases, and `contains` agrees with `mark`.
//! Поток 16-битных номеров в окно приёма: без паники, номер не принимается дважды,
//! `largest` не убывает, `contains` согласуется с `mark`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use voidnet_core::window::{Class, RecvWindow};

fuzz_target!(|data: &[u8]| {
    let mut win = RecvWindow::new();
    let mut prev_largest: Option<u64> = None;
    for pair in data.chunks_exact(2) {
        let pn16 = u16::from_le_bytes([pair[0], pair[1]]);
        let Some(pn) = win.reconstruct(pn16) else { continue };
        assert_eq!(pn & 0xFFFF, u64::from(pn16));
        let before = win.classify(pn);
        let class = win.mark(pn);
        assert_eq!(before, class);
        if class == Class::New {
            assert!(win.contains(pn));
            assert_eq!(win.classify(pn), Class::Duplicate);
        }
        let l = win.largest().unwrap();
        if let Some(p) = prev_largest {
            assert!(l >= p);
        }
        prev_largest = Some(l);
    }
});
