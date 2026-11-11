//! Any bytes: the parser must not panic, and whatever parses must encode back to the
//! same bytes (one valid encoding per datagram, docs/wire.md section 0).
//! Любые байты: разбор не паникует, а всё, что разобралось, кодируется обратно в те же байты.
#![no_main]

use libfuzzer_sys::fuzz_target;
use voidnet_core::wire::{self, ChannelMode, Datagram, MAX_DATAGRAM};

const TABLES: [&[ChannelMode]; 4] = [
    &[],
    &[ChannelMode::Unreliable],
    &[
        ChannelMode::ReliableOrdered,
        ChannelMode::Unreliable,
        ChannelMode::UnreliableSequenced,
    ],
    &[ChannelMode::UnreliableSequenced; 16],
];

fuzz_target!(|data: &[u8]| {
    // the first byte picks the channel table, the rest is the datagram
    let Some((&sel, dg)) = data.split_first() else { return };
    let channels = TABLES[usize::from(sel) % TABLES.len()];
    if let Ok(d) = wire::parse(dg, channels) {
        let mut out = [0u8; MAX_DATAGRAM + 16];
        let n = wire::encode(&d, &mut out).expect("a parsed datagram must re-encode");
        assert_eq!(&out[..n], dg, "re-encoding changed the bytes");
        if let Datagram::Data(dd) = d {
            let frames = dd.frames().count();
            assert!(frames >= 1 && frames <= dg.len());
        }
    }
});
