//! Stage 5: when a datagram is built (see docs/transmit.md). A datagram starts only on an explicit
//! `flush` or when a timer fires; an acknowledgement rides on the nearest datagram and leaves alone
//! only after `max_ack_delay`.
//! Этап 5: когда строится датаграмма. Только по явному `flush` или по таймеру; подтверждение
//! едет с ближайшей датаграммой и уходит отдельно лишь через `max_ack_delay`.

use voidnet_core::conn::{Conn, ConnConfig, REL_WINDOW};
use voidnet_core::wire::{self, ChannelMode, Datagram};
use voidnet_core::ChannelTable;
use voidnet_sim::pair::Pair;
use voidnet_sim::Params;

const RELIABLE: u8 = 0;
const UNRELIABLE: u8 = 1;
const DELAY: u64 = 20_000;
const LATENCY: u64 = 5_000;
const TOKEN: u64 = 0x1357_9BDF_0246_8ACE;

fn cfg(max_ack_delay_us: u64) -> ConnConfig {
    ConnConfig {
        channels: ChannelTable::new(&[
            ChannelMode::ReliableOrdered,
            ChannelMode::Unreliable,
            ChannelMode::UnreliableSequenced,
        ])
        .unwrap(),
        max_ack_delay_us,
        keepalive_us: 1_000_000,
        initial_rtt_us: 100_000,
    }
}

fn clean(max_ack_delay_us: u64) -> Pair {
    Pair::new(
        cfg(max_ack_delay_us),
        Params {
            latency_us: LATENCY,
            ..Params::default()
        },
        1,
    )
}

fn drain(c: &mut Conn) -> Vec<(u8, Vec<u8>)> {
    let mut v = Vec::new();
    while let Some(d) = c.poll_recv() {
        v.push((d.ch, d.payload().to_vec()));
    }
    v
}

// ------------------------------------------------------------------ nothing without flush

#[test]
fn nothing_leaves_without_a_flush_or_a_timer() {
    let mut p = clean(DELAY);
    p.a.conn.send(RELIABLE, b"reliable").unwrap();
    p.a.conn.send(UNRELIABLE, b"unreliable").unwrap();
    // 900 ms: well inside the keep-alive period of one second
    p.run_for(900_000);
    assert_eq!(p.a.sent.len(), 0, "send alone must not start a datagram");
    assert_eq!(p.b.sent.len(), 0);
    assert!(drain(&mut p.b.conn).is_empty());
    assert_eq!(p.a.conn.stats().packets_sent, 0);

    p.a.conn.flush();
    p.run_for(50_000);
    assert_eq!(
        p.a.sent.len(),
        1,
        "one flush, one datagram for both messages"
    );
    let got = drain(&mut p.b.conn);
    assert!(got.contains(&(RELIABLE, b"reliable".to_vec())));
    assert!(got.contains(&(UNRELIABLE, b"unreliable".to_vec())));
}

#[test]
fn a_message_without_flush_rides_with_the_next_flush() {
    let mut p = clean(DELAY);
    p.a.conn.send(UNRELIABLE, b"one").unwrap();
    p.run_for(10_000);
    assert_eq!(p.a.sent.len(), 0);
    p.a.conn.send(UNRELIABLE, b"two").unwrap();
    p.a.conn.flush();
    p.run_for(15_000);
    assert_eq!(p.a.sent.len(), 1, "both in the same datagram");
    assert_eq!(
        drain(&mut p.b.conn),
        vec![(UNRELIABLE, b"one".to_vec()), (UNRELIABLE, b"two".to_vec())]
    );
}

#[test]
fn a_message_nobody_flushed_leaves_with_the_keep_alive_datagram() {
    let mut p = clean(DELAY);
    p.a.conn.send(RELIABLE, b"patient").unwrap();
    p.run_for(1_050_000);
    let s = p.a.conn.stats();
    assert_eq!(
        s.packets_sent - s.ack_only_sent,
        1,
        "the keep-alive datagram carries it"
    );
    assert_eq!(drain(&mut p.b.conn), vec![(RELIABLE, b"patient".to_vec())]);
}

#[test]
fn a_flush_does_not_linger_after_it_has_been_served() {
    let mut p = clean(DELAY);
    p.ba.params_mut().loss_permille = 1000; // no acknowledgement gets back to clean up after it
    p.a.conn.send(UNRELIABLE, b"first").unwrap();
    p.a.conn.flush();
    p.run_for(50_000);
    assert_eq!(p.a.sent.len(), 1);
    p.a.conn.send(UNRELIABLE, b"second").unwrap(); // no flush
    p.run_for(200_000); // less than a probe timeout without an acknowledgement
    assert_eq!(
        p.a.sent.len(),
        1,
        "the old flush must not send the new message"
    );
    assert_eq!(drain(&mut p.b.conn).len(), 1);
}

#[test]
fn a_flush_does_not_outlive_the_queue_it_was_for() {
    // The queue can empty without a datagram: a reliable message is queued again because its
    // first packet is declared lost, while a probe copy of it is still on its way; the copy is
    // acknowledged. The flush the host made for that queue is spent. A message queued afterwards
    // without a flush must wait for the next one.
    let c = cfg(DELAY);
    let (mut a, mut b) = (Conn::new(TOKEN, c, 0), Conn::new(TOKEN, c, 0));
    let mut buf = [0u8; 1500];
    let deliver = |to: &mut Conn, d: &[u8], now: u64| {
        let Ok(Datagram::Data(dd)) = wire::parse(d, c.channels.as_slice()) else {
            panic!("not a DATA datagram");
        };
        to.on_datagram(&dd, now).unwrap();
    };
    let mut take = |c: &mut Conn, now: u64| {
        let n = c.build(now, &mut buf).expect("a datagram");
        buf[..n].to_vec()
    };

    a.send(RELIABLE, b"R").unwrap();
    a.flush();
    let _lost = take(&mut a, 1_000); // packet 0 carries R and never arrives
    a.send(UNRELIABLE, b"u").unwrap();
    a.flush();
    let d1 = take(&mut a, 2_000); // packet 1
    deliver(&mut b, &d1, 3_000);
    let ack1 = take(&mut b, 3_000 + DELAY);

    // the probe timer fires and R goes out twice more (packets 2 and 3)
    a.on_timeout(400_000);
    let d2 = take(&mut a, 400_000);
    let _d3 = take(&mut a, 400_000);

    // the acknowledgement of packet 1 arrives late; now packet 0 is overdue: R is queued again
    deliver(&mut a, &ack1, 401_000);
    a.on_timeout(500_000);
    assert_eq!(a.stats().packets_lost, 1);
    a.flush();

    // packet 2 is acknowledged after all: R is acknowledged, the queue is empty
    deliver(&mut b, &d2, 501_000);
    let ack2 = take(&mut b, 501_000 + DELAY);
    deliver(&mut a, &ack2, 530_000);

    a.send(UNRELIABLE, b"later").unwrap(); // no flush
    assert!(
        a.build(531_000, &mut buf).is_none(),
        "a spent flush must not send the next message"
    );
    a.flush();
    assert!(a.build(531_000, &mut buf).is_some());
}

#[test]
fn a_message_declared_lost_is_repeated_at_once_without_a_flush() {
    let c = cfg(DELAY);
    let (mut a, mut b) = (Conn::new(TOKEN, c, 0), Conn::new(TOKEN, c, 0));
    let mut buf = [0u8; 1500];
    let deliver = |to: &mut Conn, d: &[u8], now: u64| {
        let Ok(Datagram::Data(dd)) = wire::parse(d, c.channels.as_slice()) else {
            panic!("not a DATA datagram");
        };
        to.on_datagram(&dd, now).unwrap();
    };
    let mut take = |c: &mut Conn, now: u64| {
        let n = c.build(now, &mut buf).expect("a datagram");
        buf[..n].to_vec()
    };
    a.send(RELIABLE, b"R").unwrap();
    a.flush();
    let _lost = take(&mut a, 1_000); // packet 0 never arrives
    for i in 0..3u64 {
        a.send(UNRELIABLE, b"u").unwrap();
        a.flush();
        let d = take(&mut a, 2_000 + i * 1_000);
        deliver(&mut b, &d, 10_000 + i * 1_000);
    }
    let ack = take(&mut b, 10_000 + DELAY);
    assert!(!a.wants_to_send(30_000), "nothing to send before the ack");
    deliver(&mut a, &ack, 30_000); // three newer packets acknowledged: packet 0 is lost
    assert_eq!(a.stats().packets_lost, 1);
    // no flush: the repeat is a timer-class send
    let d = take(&mut a, 30_000);
    deliver(&mut b, &d, 40_000);
    assert!(drain(&mut b).contains(&(RELIABLE, b"R".to_vec())));
}

#[test]
fn flush_with_nothing_queued_does_nothing_and_never_makes_an_ack_only_datagram() {
    let mut p = clean(DELAY);
    p.a.conn.send(UNRELIABLE, b"x").unwrap();
    p.a.conn.flush();
    p.run_for(LATENCY + 3_000); // arrived at b, the acknowledgement is not due yet
    assert!(p.b.conn.stats().packets_recv == 1);
    p.b.conn.flush(); // nothing queued at b
    p.run_for(10_000);
    assert_eq!(p.b.sent.len(), 0, "a flush is not a reason to acknowledge");
}

#[test]
fn a_flush_that_needs_several_datagrams_is_served_completely() {
    let mut p = clean(DELAY);
    for i in 0..12u8 {
        p.a.conn.send(RELIABLE, &[i; 400]).unwrap(); // 4800 bytes: several datagrams
    }
    p.a.conn.flush(); // one flush
    p.run_for(200_000);
    assert!(p.a.sent.len() >= 4);
    let got = drain(&mut p.b.conn);
    assert_eq!(got.len(), 12);
    for (i, (ch, m)) in got.iter().enumerate() {
        assert_eq!((*ch, m.as_slice()), (RELIABLE, &[i as u8; 400][..]));
    }
}

// ------------------------------------------------------------------ acknowledgements

#[test]
fn an_acknowledgement_waits_for_the_ack_delay_and_then_goes_alone() {
    let mut p = clean(DELAY);
    let t_send = p.now;
    // five packets, a millisecond apart: the old "every second packet" rule would have answered
    for i in 0..5u8 {
        p.a.conn.send(RELIABLE, &[i]).unwrap();
        p.a.conn.flush();
        p.step();
    }
    let first_arrival = t_send + LATENCY;
    let mut t_ack = None;
    while p.now < t_send + 200_000 && t_ack.is_none() {
        p.step();
        if !p.b.sent.is_empty() {
            t_ack = Some(p.now);
        }
    }
    let t_ack = t_ack.expect("the acknowledgement must come");
    assert!(
        t_ack >= first_arrival + DELAY && t_ack <= first_arrival + DELAY + 3_000,
        "ack at +{} us after the first arrival",
        t_ack - first_arrival
    );
    p.run_for(100_000);
    assert_eq!(p.b.sent.len(), 1, "one datagram acknowledges all five");
    let s = p.b.conn.stats();
    assert_eq!((s.packets_sent, s.ack_only_sent), (1, 1));
    // it did its job: five messages are acknowledged, the sender measured a round trip
    let a = p.a.conn.stats();
    assert!(a.rtt_us > 0 && a.packets_lost == 0);
    for i in 0..REL_WINDOW {
        assert!(
            p.a.conn.send(RELIABLE, &[i as u8]).is_ok(),
            "the window is free again"
        );
    }
}

#[test]
fn a_ping_is_acknowledged_after_the_delay_like_everything_else() {
    let mut p = clean(DELAY);
    p.a.conn.queue_ping();
    p.run_for(LATENCY + DELAY / 2);
    assert_eq!(p.a.sent.len(), 1, "the PING itself leaves at once");
    assert_eq!(p.b.sent.len(), 0, "its acknowledgement waits");
    p.run_for(DELAY);
    assert_eq!(p.b.sent.len(), 1);
}

#[test]
fn acknowledgements_ride_on_flushed_datagrams_in_a_two_way_flow() {
    // 25 packets a second one way, 50 the other, both flushed; a delay longer than both gaps
    let mut p = clean(60_000);
    let (mut na, mut nb) = (p.now, p.now);
    let mut sent_reliable = 0;
    while p.now < 1_000_000 + 5_000_000 {
        if p.now >= na {
            na += 40_000;
            // a reliable message each time: the window never fills only if acks come back
            p.a.conn
                .send(RELIABLE, &[0u8; 20])
                .expect("acknowledgements arrive");
            sent_reliable += 1;
            p.a.conn.flush();
        }
        if p.now >= nb {
            nb += 20_000;
            p.b.conn.send(UNRELIABLE, &[1u8; 100]).unwrap();
            p.b.conn.flush();
        }
        p.step();
        drain(&mut p.a.conn);
        drain(&mut p.b.conn);
    }
    let (a, b) = (p.a.conn.stats(), p.b.conn.stats());
    assert_eq!(a.ack_only_sent, 0);
    assert_eq!(b.ack_only_sent, 0);
    assert_eq!(
        a.packets_sent, sent_reliable,
        "one datagram per flush, nothing else"
    );
    assert!(a.rtt_us > 0 && b.rtt_us > 0);
}

#[test]
fn a_standalone_acknowledgement_appears_only_when_the_reverse_gap_is_longer_than_the_delay() {
    // b sends every 100 ms; a sends every 20 ms and needs its datagrams acknowledged
    for (delay, expect_alone) in [(20_000u64, true), (150_000, false)] {
        let mut p = clean(delay);
        let (mut na, mut nb) = (p.now, p.now);
        while p.now < 1_000_000 + 5_000_000 {
            if p.now >= na {
                na += 20_000;
                p.a.conn.send(UNRELIABLE, &[1u8; 50]).unwrap();
                p.a.conn.flush();
            }
            if p.now >= nb {
                nb += 100_000;
                p.b.conn.send(UNRELIABLE, &[2u8; 50]).unwrap();
                p.b.conn.flush();
            }
            p.step();
            drain(&mut p.a.conn);
            drain(&mut p.b.conn);
        }
        let b = p.b.conn.stats();
        assert_eq!(b.ack_only_sent > 0, expect_alone, "delay {delay}: {b:?}");
        // and never more than one per delay: the delay is a real rate limit
        assert!(b.ack_only_sent <= 5_000_000 / delay + 1, "{b:?}");
    }
}

// ------------------------------------------------------------------ timers still work

fn lossy(loss_permille: u32) -> Params {
    Params {
        latency_us: 25_000,
        jitter_us: 15_000,
        loss_permille,
        dup_permille: 50,
        reorder_permille: 100,
        reorder_delay_us: 40_000,
        ..Params::default()
    }
}

#[test]
fn lost_reliable_messages_are_repeated_without_any_further_flush() {
    let mut resent = 0;
    for seed in 0..8u64 {
        let mut p = Pair::new(cfg(DELAY), lossy(250), seed);
        // one burst, one flush, never again: only the timers may send from here on
        let mut queued = 0u32;
        while p.a.conn.send(RELIABLE, &queued.to_le_bytes()).is_ok() {
            queued += 1;
        }
        assert_eq!(queued as usize, REL_WINDOW);
        p.a.conn.flush();
        let mut got = Vec::new();
        p.run_until(60_000_000, |p| {
            got.extend(
                drain(&mut p.b.conn)
                    .into_iter()
                    .map(|(_, m)| u32::from_le_bytes(m.try_into().unwrap())),
            );
            got.len() as u32 == queued
        });
        assert_eq!(got, (0..queued).collect::<Vec<_>>(), "seed {seed}");
        resent += p.a.conn.stats().messages_resent;
    }
    assert!(
        resent > 0,
        "the links did drop packets, so something was repeated"
    );
}

#[test]
fn a_reliable_stream_with_a_flush_per_burst_survives_loss_and_jitter() {
    for seed in 0..6u64 {
        let mut p = Pair::new(cfg(DELAY), lossy(200), seed);
        let (mut next, mut got) = (0u32, Vec::new());
        let total = 300u32;
        let mut tick = 0u64;
        p.run_until(120_000_000, |p| {
            tick += 1;
            // a burst of messages every 20 ms, flushed once; the rest rides on timers
            if tick.is_multiple_of(20) {
                for _ in 0..3 {
                    if next < total && p.a.conn.send(RELIABLE, &next.to_le_bytes()).is_ok() {
                        next += 1;
                    }
                }
                p.a.conn.flush();
            }
            got.extend(
                drain(&mut p.b.conn)
                    .into_iter()
                    .map(|(_, m)| u32::from_le_bytes(m.try_into().unwrap())),
            );
            got.len() as u32 == total
        });
        assert_eq!(
            got,
            (0..total).collect::<Vec<_>>(),
            "seed {seed}: in order, each once"
        );
    }
}
