//! Stage 3: delivery modes, acknowledgements, RTT, loss recovery, probes, keep-alive.
//! Two established connections through lossy links (no handshake): see `pair.rs`.
//! Этап 3: режимы доставки, подтверждения, RTT, восстановление после потерь, пробы, keep-alive.

use voidnet_core::conn::{ConnConfig, SendError, MSG_MAX, REL_WINDOW};
use voidnet_core::wire::{self, ChannelMode, DataWriter, Datagram};
use voidnet_core::ChannelTable;
use voidnet_sim::pair::Pair;
use voidnet_sim::{Params, Pcg32};

const RELIABLE: u8 = 0;
const UNRELIABLE: u8 = 1;
const SEQUENCED: u8 = 2;

fn cfg() -> ConnConfig {
    ConnConfig {
        channels: ChannelTable::new(&[
            ChannelMode::ReliableOrdered,
            ChannelMode::Unreliable,
            ChannelMode::UnreliableSequenced,
        ])
        .unwrap(),
        max_ack_delay_us: 20_000,
        keepalive_us: 1_000_000,
        initial_rtt_us: 100_000,
    }
}

fn clean(latency_us: u64) -> Params {
    Params {
        latency_us,
        ..Params::default()
    }
}

fn hostile() -> Params {
    Params {
        latency_us: 25_000,
        jitter_us: 10_000,
        loss_permille: 250,
        dup_permille: 100,
        reorder_permille: 150,
        reorder_delay_us: 40_000,
        ..Params::default()
    }
}

/// A message that carries its own index and a checkable body of a varying size.
fn body(i: u32, rng: &mut Pcg32) -> Vec<u8> {
    let len = 4 + rng.below(if i.is_multiple_of(50) {
        MSG_MAX as u32 - 4
    } else {
        200
    }) as usize;
    let mut v = vec![0u8; len];
    v[..4].copy_from_slice(&i.to_le_bytes());
    for (k, b) in v.iter_mut().enumerate().skip(4) {
        *b = (i as usize).wrapping_mul(31).wrapping_add(k) as u8;
    }
    v
}

fn check_body(data: &[u8]) -> u32 {
    let i = u32::from_le_bytes(data[..4].try_into().unwrap());
    for (k, b) in data.iter().enumerate().skip(4) {
        assert_eq!(
            *b,
            (i as usize).wrapping_mul(31).wrapping_add(k) as u8,
            "message {i} corrupted at {k}"
        );
    }
    i
}

// ------------------------------------------------------------------ P1: reliable, ordered, once

#[test]
fn reliable_arrives_once_in_order_over_a_hostile_link() {
    for seed in 0..30u64 {
        let mut p = Pair::new(cfg(), hostile(), seed);
        let mut rng = Pcg32::new(seed, 9);
        let total = 400u32;
        let (mut next_send, mut got) = (0u32, Vec::new());
        let ok = p.run_until(120_000_000, |p| {
            // the host sends while the window has room and receives whatever is ready
            while next_send < total {
                match p.a.conn.send(RELIABLE, &body(next_send, &mut rng.clone())) {
                    Ok(()) => {
                        // advance the generator state the same way the clone did
                        let _ = body(next_send, &mut rng);
                        next_send += 1;
                    }
                    Err(SendError::Full) => break,
                    Err(e) => panic!("{e:?}"),
                }
            }
            while let Some(d) = p.b.conn.poll_recv() {
                assert_eq!(d.ch, RELIABLE);
                got.push(check_body(d.payload()));
            }
            got.len() as u32 == total
        });
        assert!(
            ok,
            "seed {seed}: got {} of {total}, stats {:?}",
            got.len(),
            p.a.conn.stats()
        );
        assert!(
            got.iter().copied().eq(0..total),
            "seed {seed}: not in order exactly once"
        );
    }
}

// ------------------------------------------------------------------ P2 and P3: the unreliable modes

#[test]
fn sequenced_never_goes_back_and_never_repeats() {
    let mut p = Pair::new(cfg(), hostile(), 1);
    let mut rng = Pcg32::new(1, 1);
    let (mut sent, mut got) = (0u32, Vec::<u32>::new());
    p.run_until(30_000_000, |p| {
        if sent < 3000 && p.now % 10_000 == 0 {
            p.a.conn.send(SEQUENCED, &body(sent, &mut rng)).unwrap();
            sent += 1;
        }
        while let Some(d) = p.b.conn.poll_recv() {
            got.push(check_body(d.payload()));
        }
        sent >= 3000 && p.now > 1_000_000 + 3000 * 10_000 + 2_000_000
    });
    assert!(got.len() > 1500, "delivered {}", got.len());
    assert!(
        got.windows(2).all(|w| w[0] < w[1]),
        "a sequenced channel must only move forward"
    );
}

#[test]
fn unreliable_is_never_delivered_twice_even_when_the_link_duplicates() {
    let mut p = Pair::new(cfg(), hostile(), 2);
    let mut rng = Pcg32::new(2, 2);
    let (mut sent, mut got) = (0u32, std::collections::HashSet::new());
    p.run_until(30_000_000, |p| {
        if sent < 3000 && p.now % 10_000 == 0 {
            p.a.conn.send(UNRELIABLE, &body(sent, &mut rng)).unwrap();
            sent += 1;
        }
        while let Some(d) = p.b.conn.poll_recv() {
            assert!(got.insert(check_body(d.payload())), "delivered twice");
        }
        sent >= 3000 && p.now > 1_000_000 + 3000 * 10_000 + 2_000_000
    });
    assert!(
        got.len() > 1500 && got.len() <= 3000,
        "delivered {}",
        got.len()
    );
}

#[test]
fn unreliable_never_waits_for_anything() {
    // the path is completely dark: nothing is queued up behind retransmissions, the newest
    // messages replace the oldest ones
    let mut p = Pair::new(cfg(), clean(10_000), 3);
    p.ab.params_mut().loss_permille = 1000;
    for i in 0..100u32 {
        p.a.conn.send(UNRELIABLE, &i.to_le_bytes()).unwrap();
    }
    p.run_for(200_000);
    assert!(
        p.a.conn.stats().unreliable_dropped >= 90,
        "{:?}",
        p.a.conn.stats()
    );
    // the link comes back: only the newest few arrive, no backlog
    p.ab.params_mut().loss_permille = 0;
    for i in 100..105u32 {
        p.a.conn.send(UNRELIABLE, &i.to_le_bytes()).unwrap();
    }
    p.run_for(300_000);
    let mut got = Vec::new();
    while let Some(d) = p.b.conn.poll_recv() {
        got.push(u32::from_le_bytes(d.payload().try_into().unwrap()));
    }
    assert_eq!(got, [100, 101, 102, 103, 104]);
}

// ------------------------------------------------------------------ P4: packet numbers

#[test]
fn packet_numbers_only_go_up_and_never_repeat() {
    let mut p = Pair::new(cfg(), hostile(), 4);
    let mut rng = Pcg32::new(4, 4);
    let mut n = 0u32;
    // enough traffic to wrap the 16-bit packet number
    p.run_until(2_000_000_000, |p| {
        if n < 400_000 {
            for _ in 0..3 {
                let _ = p.a.conn.send(RELIABLE, &body(n, &mut rng));
                let _ = p.a.conn.send(UNRELIABLE, &body(n, &mut rng));
                n += 1;
            }
        }
        while p.b.conn.poll_recv().is_some() {}
        p.a.sent.len() > 70_000
    });
    let chans = cfg().channels;
    let mut last: Option<u64> = None;
    for d in &p.a.sent {
        let Ok(Datagram::Data(dd)) = wire::parse(d, chans.as_slice()) else {
            panic!()
        };
        // reconstruct the full number the way a receiver would
        let full = match last {
            None => u64::from(dd.pn),
            Some(l) => {
                let base = (l + 1) & !0xFFFF;
                let c = base | u64::from(dd.pn);
                if c + 0x8000 <= l + 1 {
                    c + 0x1_0000
                } else {
                    c
                }
            }
        };
        if let Some(l) = last {
            assert_eq!(full, l + 1, "packet numbers must be consecutive");
        }
        last = Some(full);
    }
    assert!(
        last.unwrap() > 65_536,
        "the 16-bit number must have wrapped: {last:?}"
    );
}

// ------------------------------------------------------------------ P6: RTT

#[test]
fn rtt_converges_to_the_real_round_trip() {
    let mut p = Pair::new(cfg(), clean(40_000), 5);
    let mut rng = Pcg32::new(5, 5);
    for i in 0..400u32 {
        p.a.conn.send(UNRELIABLE, &body(i, &mut rng)).unwrap();
        p.b.conn.send(UNRELIABLE, &body(i, &mut rng)).unwrap();
        p.run_for(25_000);
        while p.a.conn.poll_recv().is_some() {}
        while p.b.conn.poll_recv().is_some() {}
    }
    for s in [p.a.conn.stats(), p.b.conn.stats()] {
        // true RTT is 80 ms; the one-tick simulation step adds up to 2 ms
        assert!((78_000..=90_000).contains(&s.rtt_us), "srtt {}", s.rtt_us);
        assert!(s.min_rtt_us >= 78_000, "min {}", s.min_rtt_us);
        assert!(s.rtt_var_us < 15_000, "var {}", s.rtt_var_us);
    }
}

#[test]
fn acknowledgement_delay_is_not_counted_as_network_time() {
    // peers answer only after the full ack delay (no traffic to ride on)
    let mut c = cfg();
    c.max_ack_delay_us = 25_000;
    let mut p = Pair::new(c, clean(30_000), 6);
    for _ in 0..20 {
        p.a.conn.send(UNRELIABLE, b"ping me").unwrap();
        p.run_for(300_000);
        while p.b.conn.poll_recv().is_some() {}
    }
    let s = p.a.conn.stats();
    assert!(
        (58_000..=66_000).contains(&s.rtt_us),
        "srtt {} should be about 60 ms, not 85",
        s.rtt_us
    );
}

// ------------------------------------------------------------------ P7: probes and recovery

#[test]
fn a_dead_path_is_probed_with_backoff_and_recovers() {
    let mut p = Pair::new(cfg(), clean(20_000), 7);
    p.a.conn.send(RELIABLE, b"before").unwrap();
    p.run_for(500_000);
    assert_eq!(p.b.conn.poll_recv().unwrap().payload(), b"before");

    // the path goes dark for 10 s while a message is waiting
    p.ab.params_mut().loss_permille = 1000;
    p.ba.params_mut().loss_permille = 1000;
    p.a.conn.send(RELIABLE, b"during").unwrap();
    let sent_before = p.a.conn.stats().packets_sent;
    p.run_for(10_000_000);
    let probes = p.a.conn.stats().packets_sent - sent_before;
    assert!(probes >= 5, "it must keep trying: {probes}");
    assert!(
        probes <= 40,
        "but with exponential backoff, not a flood: {probes} packets in 10 s"
    );

    // the path comes back: the message arrives without anyone asking again
    p.ab.params_mut().loss_permille = 0;
    p.ba.params_mut().loss_permille = 0;
    assert!(p.run_until(30_000_000, |p| p.b.conn.has_delivery()));
    assert_eq!(p.b.conn.poll_recv().unwrap().payload(), b"during");
}

#[test]
fn a_single_lost_message_is_repaired_within_about_one_round_trip() {
    let mut p = Pair::new(cfg(), clean(25_000), 8);
    // warm up so the connection has an RTT estimate
    for _ in 0..30 {
        p.a.conn.send(UNRELIABLE, b"w").unwrap();
        p.run_for(60_000);
        while p.b.conn.poll_recv().is_some() {}
    }
    // lose exactly the datagram that carries the reliable message
    p.ab.params_mut().loss_permille = 1000;
    p.a.conn.send(RELIABLE, b"important").unwrap();
    p.run_for(2_000);
    p.ab.params_mut().loss_permille = 0;
    let t0 = p.now;
    // ordinary traffic follows, as in a game
    let mut i = 0u32;
    let done = p.run_until(5_000_000, |p| {
        if p.now % 20_000 == 0 {
            p.a.conn.send(UNRELIABLE, &i.to_le_bytes()).unwrap();
            i += 1;
        }
        while let Some(d) = p.b.conn.poll_recv() {
            if d.ch == RELIABLE {
                return true;
            }
        }
        false
    });
    assert!(done);
    let took = p.now - t0;
    assert!(
        took < 250_000,
        "repaired after {} ms, expected well under a quarter of a second",
        took / 1000
    );
    assert!(p.a.conn.stats().messages_resent >= 1);
}

// ------------------------------------------------------------------ backpressure and windows

#[test]
fn the_reliable_window_says_full_and_nothing_is_half_accepted() {
    let mut p = Pair::new(cfg(), clean(10_000), 9);
    p.ab.params_mut().loss_permille = 1000; // nothing is acknowledged
    for i in 0..REL_WINDOW as u32 {
        p.a.conn.send(RELIABLE, &i.to_le_bytes()).unwrap();
    }
    assert_eq!(
        p.a.conn.send(RELIABLE, b"one too many"),
        Err(SendError::Full)
    );
    // a refusal leaves the queue as it was: after the link heals exactly 16 arrive, in order
    p.ab.params_mut().loss_permille = 0;
    let mut got = Vec::new();
    p.run_until(10_000_000, |p| {
        while let Some(d) = p.b.conn.poll_recv() {
            got.push(u32::from_le_bytes(d.payload().try_into().unwrap()));
        }
        got.len() == REL_WINDOW
    });
    assert_eq!(got, (0..REL_WINDOW as u32).collect::<Vec<_>>());
    // and the window is open again
    p.run_for(500_000);
    assert!(p.a.conn.send(RELIABLE, b"now it fits").is_ok());
}

#[test]
fn a_slow_host_applies_backpressure_instead_of_losing_reliable_messages() {
    // the receiver does not read for a long time: nothing may be lost, nothing delivered early
    let mut p = Pair::new(cfg(), hostile(), 10);
    let mut rng = Pcg32::new(10, 10);
    let total = 120u32;
    let (mut next, mut got) = (0u32, Vec::new());
    p.run_until(60_000_000, |p| {
        while next < total {
            match p.a.conn.send(RELIABLE, &body(next, &mut rng)) {
                Ok(()) => next += 1,
                Err(SendError::Full) => break,
                Err(e) => panic!("{e:?}"),
            }
        }
        // the host reads only once in a while, and only two at a time
        if p.now % 400_000 == 0 {
            for _ in 0..2 {
                if let Some(d) = p.b.conn.poll_recv() {
                    got.push(check_body(d.payload()));
                }
            }
        }
        got.len() as u32 == total
    });
    assert!(
        got.iter().copied().eq(0..total),
        "lost or reordered: got {}",
        got.len()
    );
}

#[test]
fn the_wrong_token_and_out_of_window_messages_change_nothing() {
    let mut p = Pair::new(cfg(), clean(10_000), 11);
    let chans = cfg().channels;
    let mut buf = [0u8; 1400];
    // wrong token
    let mut w = DataWriter::new(&mut buf, chans.as_slice(), 0xBAD, 0).unwrap();
    w.msg(RELIABLE, Some(0), b"x").unwrap();
    let n = w.finish().unwrap();
    let Ok(Datagram::Data(dd)) = wire::parse(&buf[..n], chans.as_slice()) else {
        panic!()
    };
    assert!(p.b.conn.on_datagram(&dd, 1).is_err());
    // right token, reliable message 1000 ahead of the window: refused, not acknowledged
    let mut w = DataWriter::new(&mut buf, chans.as_slice(), 0x1357_9BDF_0246_8ACE, 1).unwrap();
    w.msg(RELIABLE, Some(1000), b"far").unwrap();
    let n = w.finish().unwrap();
    let Ok(Datagram::Data(dd)) = wire::parse(&buf[..n], chans.as_slice()) else {
        panic!()
    };
    assert!(p.b.conn.on_datagram(&dd, 1).is_err());
    assert!(!p.b.conn.has_delivery());
    assert_eq!(
        p.b.conn.stats().packets_recv,
        0,
        "a refused datagram is not counted as received"
    );
}

// ------------------------------------------------------------------ packet economy

#[test]
fn steady_game_traffic_needs_almost_no_ack_only_datagrams() {
    // 50 Hz both ways, like input and snapshots
    let mut c = cfg();
    c.max_ack_delay_us = 20_000;
    let mut p = Pair::new(c, clean(25_000), 12);
    let mut rng = Pcg32::new(12, 12);
    for i in 0..500u32 {
        p.a.conn.send(UNRELIABLE, &body(i, &mut rng)).unwrap();
        p.b.conn.send(UNRELIABLE, &body(i, &mut rng)).unwrap();
        p.run_for(20_000);
        while p.a.conn.poll_recv().is_some() {}
        while p.b.conn.poll_recv().is_some() {}
    }
    for s in [p.a.conn.stats(), p.b.conn.stats()] {
        let per_second = s.packets_sent as f64 / 10.0;
        assert!(
            (45.0..=60.0).contains(&per_second),
            "{per_second} datagrams per second, expected about 50"
        );
        assert!(
            s.ack_only_sent * 20 < s.packets_sent,
            "ack-only {} of {}",
            s.ack_only_sent,
            s.packets_sent
        );
    }
}

#[test]
fn an_idle_connection_keeps_itself_alive_and_measured() {
    let mut p = Pair::new(cfg(), clean(30_000), 13);
    p.run_for(10_000_000);
    for s in [p.a.conn.stats(), p.b.conn.stats()] {
        assert!(
            (8..=22).contains(&s.packets_sent),
            "idle traffic should be one or two datagrams a second: {}",
            s.packets_sent
        );
        assert!((55_000..=70_000).contains(&s.rtt_us), "srtt {}", s.rtt_us);
    }
}

#[test]
fn a_whole_exchange_is_reproducible() {
    let run = |seed: u64| {
        let mut p = Pair::new(cfg(), hostile(), seed);
        let mut rng = Pcg32::new(seed, 1);
        let mut n = 0u32;
        p.run_until(20_000_000, |p| {
            if n < 200 && p.a.conn.send(RELIABLE, &body(n, &mut rng)).is_ok() {
                n += 1;
            }
            while p.b.conn.poll_recv().is_some() {}
            false
        });
        (
            p.ab.trace(),
            p.ba.trace(),
            p.a.conn.stats(),
            p.b.conn.stats(),
        )
    };
    assert_eq!(run(3), run(3));
    assert_ne!(run(3).0, run(4).0);
}
