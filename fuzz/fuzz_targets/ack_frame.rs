//! Arbitrary bytes as an ACK frame body: no panic; a frame that reads must write back
//! to the bytes it consumed, and its ranges must be well formed.
//! Произвольные байты как тело ACK: без паники; прочитанный кадр записывается обратно в те
//! же байты, диапазоны корректны.
#![no_main]

use libfuzzer_sys::fuzz_target;
use voidnet_core::ack::{reconstruct_largest, AckFrame};
use voidnet_core::io::{Reader, Writer};

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let Ok(frame) = AckFrame::read(&mut r) else { return };
    let used = data.len() - r.remaining();

    let mut out = [0u8; 128];
    let mut w = Writer::new(&mut out, 128);
    frame.write(&mut w).expect("a frame that reads must write");
    let written = w.pos();
    assert_eq!(&out[..written], &data[..used]);

    assert!(frame.span() <= 1 << 15);
    for highest in [0u64, 1, 70_000, u64::MAX] {
        if let Some(full) = reconstruct_largest(highest, frame.largest) {
            assert!(full <= highest);
            if let Some(ranges) = frame.ranges(full) {
                let mut upper: Option<u64> = None;
                for (lo, hi) in ranges {
                    assert!(lo <= hi && upper.map_or(true, |u| hi < u));
                    upper = Some(lo);
                }
            }
        }
    }
});
