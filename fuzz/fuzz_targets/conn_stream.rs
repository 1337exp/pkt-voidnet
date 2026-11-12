//! Two connections in a fuzz-controlled world: the input decides what is sent, which datagram
//! is delivered, duplicated, dropped or delayed, and how time passes. The invariants are the
//! delivery guarantees themselves.
//!
//! - reliable: what the receiver hands to the host is always an exact prefix of what was sent
//!   (in order, no gap, no repeat)
//! - sequenced: strictly increasing
//! - unreliable: never repeated
//! - nothing panics, whatever bytes arrive with a valid token
//!
//! Два соединения в мире, которым управляет фаззер: он решает, что отправить, какую датаграмму
//! доставить, продублировать, потерять или задержать и как идёт время. Инварианты это сами
//! гарантии доставки.
#![no_main]

use libfuzzer_sys::fuzz_target;
use voidnet_core::conn::{Conn, ConnConfig, MSG_MAX};
use voidnet_core::wire::{self, ChannelMode, Datagram};
use voidnet_core::ChannelTable;

const TOKEN: u64 = 0x1357_9BDF_0246_8ACE;
const RELIABLE: u8 = 0;
const UNRELIABLE: u8 = 1;
const SEQUENCED: u8 = 2;

struct Side {
    conn: Box<Conn>,
    out: Vec<Vec<u8>>,
    sent_reliable: u32,
    sent_other: u32,
    got_reliable: u32,
    got_sequenced_last: Option<u32>,
    got_unreliable: std::collections::HashSet<u32>,
}

impl Side {
    fn new(cfg: ConnConfig) -> Self {
        Self {
            conn: Box::new(Conn::new(TOKEN, cfg, 1_000_000)),
            out: Vec::new(),
            sent_reliable: 0,
            sent_other: 0,
            got_reliable: 0,
            got_sequenced_last: None,
            got_unreliable: Default::default(),
        }
    }

    fn payload(kind: u8, idx: u32, extra: usize) -> Vec<u8> {
        let mut v = vec![kind];
        v.extend_from_slice(&idx.to_le_bytes());
        v.resize(5 + extra.min(MSG_MAX - 5), 0xAB);
        v
    }

    fn drain_recv(&mut self) {
        while let Some(d) = self.conn.poll_recv() {
            let p = d.payload();
            assert!(p.len() >= 5);
            let idx = u32::from_le_bytes([p[1], p[2], p[3], p[4]]);
            match d.ch {
                RELIABLE => {
                    assert_eq!(idx, self.got_reliable, "reliable stream must be an exact prefix");
                    self.got_reliable += 1;
                }
                SEQUENCED => {
                    if let Some(l) = self.got_sequenced_last {
                        assert!(idx > l, "sequenced went back");
                    }
                    self.got_sequenced_last = Some(idx);
                }
                _ => assert!(self.got_unreliable.insert(idx), "unreliable delivered twice"),
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let channels = ChannelTable::new(&[
        ChannelMode::ReliableOrdered,
        ChannelMode::Unreliable,
        ChannelMode::UnreliableSequenced,
    ])
    .unwrap();
    let cfg = ConnConfig {
        channels,
        max_ack_delay_us: 20_000,
        keepalive_us: 500_000,
        initial_rtt_us: 100_000,
    };
    let mut sides = [Side::new(cfg), Side::new(cfg)];
    let mut now = 1_000_000u64;
    let mut it = data.iter().copied();
    let mut buf = [0u8; 1500];

    while let (Some(op), Some(arg)) = (it.next(), it.next()) {
        let me = usize::from(op >> 7);
        let other = 1 - me;
        match op & 0x0F {
            0 => {
                let idx = sides[me].sent_reliable;
                if sides[me]
                    .conn
                    .send(RELIABLE, &Side::payload(0, idx, usize::from(arg) * 5))
                    .is_ok()
                {
                    sides[me].sent_reliable += 1;
                }
            }
            1 => {
                let idx = sides[me].sent_other;
                let ch = if arg & 1 == 0 { UNRELIABLE } else { SEQUENCED };
                if sides[me]
                    .conn
                    .send(ch, &Side::payload(ch, idx, usize::from(arg) * 4))
                    .is_ok()
                {
                    sides[me].sent_other += 1;
                }
            }
            2 => {
                // collect what this side wants to send: with a flush (even arg) everything queued
                // is due, without it only timers start a datagram
                if arg & 1 == 0 {
                    sides[me].conn.flush();
                }
                for _ in 0..6 {
                    match sides[me].conn.build(now, &mut buf) {
                        Some(n) => {
                            let d = buf[..n].to_vec();
                            if sides[me].out.len() >= 48 {
                                sides[me].out.remove(0);
                            }
                            sides[me].out.push(d);
                        }
                        None => break,
                    }
                }
            }
            3 | 4 => {
                // deliver one datagram of the other side (op 4: keep a copy, so it repeats)
                let n = sides[other].out.len();
                if n > 0 {
                    let i = usize::from(arg) % n;
                    let d = if op & 0x0F == 4 {
                        sides[other].out[i].clone()
                    } else {
                        sides[other].out.remove(i)
                    };
                    if let Ok(Datagram::Data(dd)) = wire::parse(&d, channels.as_slice()) {
                        let _ = sides[me].conn.on_datagram(&dd, now);
                    }
                }
            }
            5 => {
                let n = sides[other].out.len();
                if n > 0 {
                    sides[other].out.remove(usize::from(arg) % n);
                }
            }
            6 => {
                now = now.saturating_add(u64::from(arg) * 4_000);
                for s in &mut sides {
                    if s.conn.next_deadline().is_some_and(|t| t <= now) {
                        s.conn.on_timeout(now);
                    }
                }
            }
            7 => sides[me].drain_recv(),
            8 => {
                // arbitrary bytes behind a valid header: must never panic, only be refused or accepted
                let mut raw = vec![0u8];
                raw.extend_from_slice(&TOKEN.to_le_bytes());
                raw.extend_from_slice(&u16::from(arg).to_le_bytes());
                raw.extend(it.by_ref().take(usize::from(arg) % 64));
                if let Ok(Datagram::Data(dd)) = wire::parse(&raw, channels.as_slice()) {
                    // garbage messages would legitimately be delivered; this op is about the
                    // other frames (acknowledgements with arbitrary ranges, pings, disconnects)
                    if !dd.frames().any(|f| matches!(f, wire::Frame::Msg { .. })) {
                        let _ = sides[me].conn.on_datagram(&dd, now);
                    }
                }
            }
            _ => now = now.saturating_add(1_000),
        }
        sides[0].drain_recv();
        sides[1].drain_recv();
    }
});
