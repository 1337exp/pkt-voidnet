//! Properties of the stage 1 core over a hostile link: packet number reconstruction across
//! wraps, no packet delivered twice, ACK frames that describe the receive window exactly.
//! Свойства ядра этапа 1 на враждебном канале: восстановление номера через переполнение,
//! ни один пакет не доставлен дважды, ACK точно описывает окно приёма.

use std::collections::HashSet;
use voidnet_core::ack::{reconstruct_largest, AckFrame};
use voidnet_core::io::{Reader, Writer};
use voidnet_core::window::{Class, RecvWindow, RECV_WINDOW};
use voidnet_core::wire::{self, ChannelMode, DataWriter, Datagram, Frame};
use voidnet_sim::{Link, Params, Pcg32};

const CH: [ChannelMode; 2] = [ChannelMode::Unreliable, ChannelMode::ReliableOrdered];

/// Send `n` datagrams that carry their own full packet number in a message, receive them
/// through `link`, and check every property.
fn pn_run(seed: u64, params: Params, n: u64) {
    let mut link = Link::new(params, seed);
    let mut win = RecvWindow::new();
    let mut accepted: HashSet<u64> = HashSet::new();
    let (mut now, mut buf) = (0u64, [0u8; 1400]);
    let mut too_old = 0u64;
    let mut dup_seen = 0u64;

    let mut deliver = |link: &mut Link, now: u64, win: &mut RecvWindow| {
        while let Some(raw) = link.poll(now) {
            let Ok(Datagram::Data(dd)) = wire::parse(&raw, &CH) else {
                panic!("a datagram we built must parse");
            };
            let full = match win.reconstruct(dd.pn) {
                Some(v) => v,
                None => panic!("pn {} negative at largest {:?}", dd.pn, win.largest()),
            };
            // the message carries the true number: reconstruction must agree with it
            let Some(Frame::Msg { payload, .. }) = dd.frames().next() else {
                panic!("no message");
            };
            let truth = u64::from_le_bytes(payload.try_into().unwrap());
            assert_eq!(full, truth, "reconstruct wrong for pn16 {}", dd.pn);
            match win.mark(full) {
                Class::New => assert!(accepted.insert(full), "pn {full} accepted twice"),
                Class::Duplicate => dup_seen += 1,
                Class::TooOld => too_old += 1,
            }
        }
    };

    for pn in 0..n {
        now += 500;
        let mut w = DataWriter::new(&mut buf, &CH, 1, (pn & 0xFFFF) as u16).unwrap();
        w.msg(0, None, &pn.to_le_bytes()).unwrap();
        let len = w.finish().unwrap();
        link.send(now, &buf[..len]);
        deliver(&mut link, now, &mut win);
    }
    now += 10_000_000;
    deliver(&mut link, now, &mut win);

    let s = link.stats;
    assert_eq!(
        accepted.len() as u64 + dup_seen + too_old,
        s.delivered,
        "every delivered datagram is classified exactly once"
    );
    assert!(dup_seen > 0 || s.duplicated == 0 || accepted.len() as u64 + too_old > 0);
    // nothing is invented: every accepted number was really sent
    assert!(accepted.iter().all(|&p| p < n));
}

#[test]
fn pn_survives_wraps_loss_duplication_and_reordering() {
    // 300k packets cross the 16-bit wrap four times. Reordering of up to 30 ms at one
    // packet per 0.5 ms keeps reordered packets within about 60 of the newest.
    pn_run(
        5,
        Params {
            latency_us: 10_000,
            jitter_us: 4_000,
            loss_permille: 100,
            dup_permille: 100,
            reorder_permille: 150,
            reorder_delay_us: 30_000,
            ..Params::default()
        },
        300_000,
    );
}

#[test]
fn pn_without_impairments_accepts_everything_once() {
    pn_run(1, Params::default(), 70_000);
}

#[test]
fn ack_frame_describes_the_window_exactly() {
    let mut rng = Pcg32::new(99, 1);
    for round in 0..2_000 {
        let mut win = RecvWindow::new();
        let mut largest = u64::from(rng.below(100_000));
        let mut model = HashSet::new();
        for _ in 0..rng.below(200) + 1 {
            // mostly newer numbers, some older ones
            let pn = if rng.chance(300) && largest > 40 {
                largest - u64::from(rng.below(40))
            } else {
                largest + u64::from(rng.below(6))
            };
            win.mark(pn);
            model.insert(pn);
            largest = largest.max(pn);
        }
        let top = win.largest().unwrap();
        let frame = AckFrame::from_window(&win, rng.below(2000)).unwrap();

        // through the wire and back
        let mut raw = [0u8; 80];
        let mut w = Writer::new(&mut raw, 80);
        frame.write(&mut w).unwrap();
        let n = w.pos();
        let back = AckFrame::read(&mut Reader::new(&raw[..n])).unwrap();
        assert_eq!(back, frame);

        // the receiver of the frame reconstructs `largest` from its own highest sent number
        let full = reconstruct_largest(top + u64::from(rng.below(30)), back.largest).unwrap();
        assert_eq!(full, top, "round {round}");

        let ranges: Vec<(u64, u64)> = back.ranges(full).unwrap().collect();
        let mut acked = HashSet::new();
        for (lo, hi) in &ranges {
            assert!(lo <= hi);
            for p in *lo..=*hi {
                assert!(acked.insert(p), "range overlap at {p}");
            }
        }
        // inside the part the frame covers, acked == received, exactly
        let covered_low = top.saturating_sub(frame.span() - 1);
        for p in covered_low..=top {
            assert_eq!(
                acked.contains(&p),
                model.contains(&p) && top - p < RECV_WINDOW,
                "pn {p} round {round}"
            );
        }
        assert!(ranges.len() <= 16);
    }
}

#[test]
fn parse_never_panics_on_random_and_mutated_input() {
    let mut rng = Pcg32::new(2026, 3);
    let mut valid = Vec::new();
    let mut buf = [0u8; 1400];
    for i in 0..300u16 {
        let mut w = DataWriter::new(&mut buf, &CH, u64::from(i), i).unwrap();
        w.msg(1, Some(i), &[i as u8; 5]).unwrap();
        w.ping().unwrap();
        let n = w.finish().unwrap();
        valid.push(buf[..n].to_vec());
    }
    for _ in 0..200_000 {
        let mut data = if rng.chance(700) {
            valid[rng.below(valid.len() as u32) as usize].clone()
        } else {
            (0..rng.below(80)).map(|_| rng.next_u32() as u8).collect()
        };
        for _ in 0..rng.below(4) {
            if !data.is_empty() {
                let i = rng.below(data.len() as u32) as usize;
                data[i] ^= 1 << rng.below(8);
            }
        }
        if let Ok(d) = wire::parse(&data, &CH) {
            // canonical: whatever parses re-encodes to the same bytes
            let mut out = [0u8; 1400];
            let n = wire::encode(&d, &mut out).unwrap();
            assert_eq!(&out[..n], &data[..]);
        }
    }
}
