//! Timers and loss detection pinned down one rule at a time, driving a connection by hand.
//! Таймеры и обнаружение потерь по одному правилу за раз, соединение ведётся вручную.

use voidnet_core::ack::AckFrame;
use voidnet_core::conn::{Conn, ConnConfig, Delivered};
use voidnet_core::window::RecvWindow;
use voidnet_core::wire::{self, ChannelMode, DataWriter, Datagram};
use voidnet_core::ChannelTable;
use voidnet_sim::pair::Pair;
use voidnet_sim::Params;

const TOKEN: u64 = 0x1357_9BDF_0246_8ACE;

fn cfg() -> ConnConfig {
    ConnConfig {
        channels: ChannelTable::new(&[ChannelMode::ReliableOrdered, ChannelMode::Unreliable])
            .unwrap(),
        max_ack_delay_us: 20_000,
        keepalive_us: 1_000_000,
        initial_rtt_us: 100_000,
    }
}

/// An ACK-only datagram from the peer that acknowledges exactly the given packet numbers.
fn ack_datagram(cfg: &ConnConfig, peer_pn: u16, acked: &[u64]) -> Vec<u8> {
    let mut win = RecvWindow::new();
    for &p in acked {
        win.mark(p);
    }
    let frame = AckFrame::from_window(&win, 0).unwrap();
    let mut buf = [0u8; 1400];
    let mut w = DataWriter::new(&mut buf, cfg.channels.as_slice(), TOKEN, peer_pn).unwrap();
    w.ack(&frame).unwrap();
    let n = w.finish().unwrap();
    buf[..n].to_vec()
}

fn feed(c: &mut Conn, cfg: &ConnConfig, bytes: &[u8], now: u64) {
    let Ok(Datagram::Data(dd)) = wire::parse(bytes, cfg.channels.as_slice()) else {
        panic!("not data")
    };
    c.on_datagram(&dd, now).expect("accepted");
}

#[test]
fn three_newer_acknowledged_packets_make_an_older_one_lost_at_once() {
    let cfg = cfg();
    let mut c = Conn::new(TOKEN, cfg, 0);
    let mut buf = [0u8; 1400];
    // four reliable messages, each in its own datagram, all at the same instant
    let t = 1_000_000;
    for i in 0..4u8 {
        c.send(0, &[i]).unwrap();
        c.flush();
        assert!(c.build(t, &mut buf).is_some(), "datagram {i}");
    }
    assert_eq!(c.stats().packets_sent, 4);
    // the peer acknowledges packets 1, 2 and 3 a moment later: packet 0 is overtaken three times
    feed(&mut c, &cfg, &ack_datagram(&cfg, 0, &[1, 2, 3]), t + 1);
    assert_eq!(
        c.stats().packets_lost,
        1,
        "packet 0 is lost by the threshold, long before any timer"
    );
    // and its message goes out again right away
    let n = c.build(t + 2, &mut buf).expect("retransmission");
    let Ok(Datagram::Data(dd)) = wire::parse(&buf[..n], cfg.channels.as_slice()) else {
        panic!()
    };
    let first = dd.frames().find_map(|f| match f {
        wire::Frame::Msg { payload, .. } => Some(payload.to_vec()),
        _ => None,
    });
    assert_eq!(first, Some(vec![0u8]));
    assert_eq!(c.stats().messages_resent, 1);
}

#[test]
fn two_newer_acknowledged_packets_are_not_enough_yet() {
    let cfg = cfg();
    let mut c = Conn::new(TOKEN, cfg, 0);
    let mut buf = [0u8; 1400];
    let t = 1_000_000;
    for i in 0..3u8 {
        c.send(0, &[i]).unwrap();
        c.flush();
        c.build(t, &mut buf).unwrap();
    }
    feed(&mut c, &cfg, &ack_datagram(&cfg, 0, &[1, 2]), t + 1);
    assert_eq!(c.stats().packets_lost, 0, "reordering by two is tolerated");
}

#[test]
fn an_old_unacknowledged_packet_is_lost_by_time_once_a_later_one_is_acknowledged() {
    let cfg = cfg();
    let mut c = Conn::new(TOKEN, cfg, 0);
    let mut buf = [0u8; 1400];
    let t = 1_000_000;
    c.send(0, &[0]).unwrap();
    c.flush();
    c.build(t, &mut buf).unwrap(); // packet 0
    c.send(0, &[1]).unwrap();
    c.flush();
    c.build(t + 400_000, &mut buf).unwrap(); // packet 1, much later
                                             // only packet 1 is acknowledged; packet 0 is 400 ms older than that, longer than 9/8 of
                                             // the assumed 100 ms round trip, and only ONE packet overtook it
    feed(&mut c, &cfg, &ack_datagram(&cfg, 0, &[1]), t + 450_000);
    assert_eq!(c.stats().packets_lost, 1);
}

#[test]
fn a_lone_lost_message_is_probed_after_about_one_pto_not_after_the_keepalive() {
    // no other traffic at all: only the probe timer can notice
    let mut p = Pair::new(
        cfg(),
        Params {
            latency_us: 25_000,
            ..Params::default()
        },
        31,
    );
    for _ in 0..10 {
        p.a.conn.send(1, b"warm up").unwrap();
        p.a.conn.flush();
        p.run_for(100_000);
        while p.b.conn.poll_recv().is_some() {}
    }
    p.ab.params_mut().loss_permille = 1000;
    p.a.conn.send(0, b"x").unwrap();
    p.a.conn.flush();
    p.run_for(3_000);
    p.ab.params_mut().loss_permille = 0;
    let t0 = p.now;
    let done = p.run_until(900_000, |p| p.b.conn.has_delivery());
    assert!(
        done,
        "must be repaired before the one-second keep-alive could do anything"
    );
    let d: Delivered = p.b.conn.poll_recv().unwrap();
    assert_eq!(d.payload(), b"x");
    assert!(p.now - t0 < 500_000, "{} ms", (p.now - t0) / 1000);
    assert!(p.a.conn.stats().probes >= 1);
}

#[test]
fn the_probe_timer_backs_off_even_if_the_host_calls_on_timeout_all_the_time() {
    let cfg = cfg();
    let mut c = Conn::new(TOKEN, cfg, 0);
    c.send(0, b"nobody answers").unwrap();
    c.flush();
    let mut buf = [0u8; 1400];
    let mut now = 1_000_000;
    let mut sent = 0;
    // 20 seconds of dead silence; the host is careless and calls on_timeout every millisecond
    for _ in 0..20_000 {
        now += 1_000;
        c.on_timeout(now);
        while c.build(now, &mut buf).is_some() {
            sent += 1;
        }
    }
    assert!(sent <= 45, "{sent} datagrams in 20 s: no backoff");
    assert!(sent >= 8, "{sent}: it must keep probing");
}

#[test]
fn a_sender_never_runs_far_ahead_of_what_the_peer_has_confirmed() {
    let cfg = cfg();
    let mut c = Conn::new(TOKEN, cfg, 0);
    let mut buf = [0u8; 1400];
    let mut now = 1_000_000;
    // 30 000 messages into a dead path, one datagram each
    for _ in 0..30_000u32 {
        now += 1_000;
        c.send(1, b"state").unwrap();
        c.flush();
        while c.build(now, &mut buf).is_some() {}
    }
    let sent = c.stats().packets_sent;
    assert!(
        sent <= 1 << 14,
        "{sent} packet numbers used without a single acknowledgement"
    );
    assert!(
        sent >= 16_000,
        "{sent}: it should use the whole allowance, then stop"
    );
}

#[test]
fn a_message_larger_than_the_profile_is_refused_whole_and_not_acknowledged() {
    let cfg = cfg();
    let mut c = Conn::new(TOKEN, cfg, 0);
    let mut buf = [0u8; 1400];
    // 1300 bytes fit a datagram but not this build's message size (1200)
    let mut w = DataWriter::new(&mut buf, cfg.channels.as_slice(), TOKEN, 0).unwrap();
    w.msg(1, None, &[7u8; 1300]).unwrap();
    let n = w.finish().unwrap();
    let Ok(Datagram::Data(dd)) = wire::parse(&buf[..n], cfg.channels.as_slice()) else {
        panic!()
    };
    assert!(c.on_datagram(&dd, 1).is_err());
    assert!(!c.has_delivery());
    assert_eq!(c.stats().packets_recv, 0);
    let mut out = [0u8; 1400];
    assert!(
        c.build(2, &mut out).is_none(),
        "nothing is owed for a datagram that was refused"
    );
}

#[test]
fn an_acknowledgement_resets_the_probe_backoff() {
    let mut p = Pair::new(
        cfg(),
        Params {
            latency_us: 25_000,
            ..Params::default()
        },
        32,
    );
    for _ in 0..10 {
        p.a.conn.send(1, b"warm up").unwrap();
        p.a.conn.flush();
        p.run_for(100_000);
        while p.b.conn.poll_recv().is_some() {}
    }
    // a long outage drives the backoff up
    p.ab.params_mut().loss_permille = 1000;
    p.ba.params_mut().loss_permille = 1000;
    p.a.conn.send(0, b"during the outage").unwrap();
    p.a.conn.flush();
    p.run_for(6_000_000);
    p.ab.params_mut().loss_permille = 0;
    p.ba.params_mut().loss_permille = 0;
    assert!(p.run_until(30_000_000, |p| p.b.conn.has_delivery()));
    p.b.conn.poll_recv();
    // life returns to normal for a while
    for _ in 0..30 {
        p.a.conn.send(1, b"normal").unwrap();
        p.a.conn.flush();
        p.run_for(100_000);
        while p.b.conn.poll_recv().is_some() {}
    }
    // a single message is lost again: the repair must be as quick as the first time, not slowed
    // by the memory of the outage
    p.ab.params_mut().loss_permille = 1000;
    p.a.conn.send(0, b"again").unwrap();
    p.a.conn.flush();
    p.run_for(3_000);
    p.ab.params_mut().loss_permille = 0;
    let t0 = p.now;
    assert!(p.run_until(900_000, |p| p.b.conn.has_delivery()));
    assert!(p.now - t0 < 500_000, "{} ms", (p.now - t0) / 1000);
}

#[test]
fn the_memory_of_a_connection_is_known_and_bounded() {
    use voidnet_core::{Client, Server};
    let conn = std::mem::size_of::<Conn>();
    let server64 = std::mem::size_of::<Server<64, 256, 160>>();
    let client = std::mem::size_of::<Client>();
    eprintln!("Conn {conn} B, Server<64,256,160> {server64} B, Client {client} B");
    // about 100 KiB per connection: 2 reliable channels x (16 + 16) slots of 1200 B, plus the
    // unreliable and delivery queues. A change here is a change of the memory budget.
    assert!((80_000..=130_000).contains(&conn), "Conn is {conn} bytes");
    assert!(
        server64 <= 64 * 130_000 + 100_000,
        "a 64-client server is {server64} bytes"
    );
}
