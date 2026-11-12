//! A game-like stream through a damaged link: ~50 small unreliable messages per second each way,
//! 60 ms one-way latency, 20 ms jitter (so datagrams are reordered), a few percent loss.
//! Looks for a connection that settles in a state where a large share of its packets is declared
//! lost although the link drops only a few percent.
//! Игровой поток через плохой канал: ~50 ненадёжных сообщений в секунду в каждую сторону.

use voidnet_core::conn::ConnConfig;
use voidnet_core::wire::ChannelMode;
use voidnet_core::ChannelTable;
use voidnet_sim::pair::Pair;
use voidnet_sim::{Params, Pcg32};

const UNRELIABLE: u8 = 1;

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

fn link(loss_permille: u32) -> Params {
    Params {
        latency_us: 60_000,
        jitter_us: 20_000,
        loss_permille,
        ..Params::default()
    }
}

/// Returns, per end, (packets sent, packets declared lost) over `seconds`, and the loss counter
/// of each second so a steady state can be told from a burst.
fn run(seed: u64, loss_permille: u32, seconds: u64) -> [(u64, u64, Vec<u64>); 2] {
    let mut p = Pair::new(cfg(), link(loss_permille), seed);
    let mut rng = Pcg32::new(seed, 7);
    let mut per_sec: [Vec<u64>; 2] = [Vec::new(), Vec::new()];
    let mut last = [0u64; 2];
    let end = p.now + seconds * 1_000_000;
    let mut next_send = p.now;
    let mut next_report = p.now + 1_000_000;
    while p.now < end {
        if p.now >= next_send {
            next_send += 20_000;
            let la = 20 + rng.below(80) as usize;
            let lb = 50 + rng.below(250) as usize;
            let _ = p.a.conn.send(UNRELIABLE, &vec![1u8; la]);
            p.a.conn.flush();
            let _ = p.b.conn.send(UNRELIABLE, &vec![2u8; lb]);
            p.b.conn.flush();
        }
        p.step();
        while p.a.conn.poll_recv().is_some() {}
        while p.b.conn.poll_recv().is_some() {}
        if p.now >= next_report {
            next_report += 1_000_000;
            for (i, e) in [&p.a, &p.b].into_iter().enumerate() {
                let l = e.conn.stats().packets_lost;
                per_sec[i].push(l - last[i]);
                last[i] = l;
            }
        }
    }
    let [sa, sb] = [p.a.conn.stats(), p.b.conn.stats()];
    let [la, lb] = per_sec;
    [
        (sa.packets_sent, sa.packets_lost, la),
        (sb.packets_sent, sb.packets_lost, lb),
    ]
}

#[test]
#[ignore = "exploration: prints the share of packets declared lost per seed"]
fn explore_loss_declared_on_a_game_like_stream() {
    for seed in 0..24u64 {
        let r = run(seed, 34, 40);
        let pct = |(s, l, _): &(u64, u64, Vec<u64>)| 100.0 * *l as f64 / (*s).max(1) as f64;
        println!(
            "seed {seed:2}: a sent {:5} lost {:4} ({:4.1}%)   b sent {:5} lost {:4} ({:4.1}%)   b per-second lost: {:?}",
            r[0].0, r[0].1, pct(&r[0]), r[1].0, r[1].1, pct(&r[1]), &r[1].2[..12.min(r[1].2.len())]
        );
    }
}

/// The game-like flow of the tee online architecture, decision 4: 50 Hz server snapshots down
/// (120 bytes, flushed each tick) and inputs up every `input_period_us` (30 bytes, flushed each).
struct Flow {
    client: voidnet_core::ConnStats,
    server: voidnet_core::ConnStats,
    inputs: u64,
    snapshots: u64,
}

fn flow(max_ack_delay_us: u64, input_period_us: u64, link: Params, seconds: u64) -> Flow {
    let c = ConnConfig {
        max_ack_delay_us,
        ..cfg()
    };
    let mut p = Pair::new(c, link, 3);
    let end = p.now + seconds * 1_000_000;
    let (mut na, mut nb) = (p.now, p.now);
    let (mut inputs, mut snapshots) = (0, 0);
    while p.now < end {
        if p.now >= na {
            na += input_period_us;
            p.a.conn.send(UNRELIABLE, &[1u8; 30]).unwrap();
            p.a.conn.flush();
            inputs += 1;
        }
        if p.now >= nb {
            nb += 20_000;
            p.b.conn.send(UNRELIABLE, &[2u8; 120]).unwrap();
            p.b.conn.flush();
            snapshots += 1;
        }
        p.step();
        while p.a.conn.poll_recv().is_some() {}
        while p.b.conn.poll_recv().is_some() {}
    }
    Flow {
        client: p.a.conn.stats(),
        server: p.b.conn.stats(),
        inputs,
        snapshots,
    }
}

fn jittery(loss_permille: u32) -> Params {
    Params {
        latency_us: 30_000,
        jitter_us: 10_000,
        loss_permille,
        ..Params::default()
    }
}

/// The game profile: a delay a little longer than the slowest regular gap of the reverse flow
/// (inputs every 50 ms), so an acknowledgement always finds a datagram to ride on.
const GAME_ACK_DELAY_US: u64 = 60_000;

#[test]
fn a_game_like_flow_sends_one_datagram_per_flush_and_no_standalone_acknowledgements() {
    for loss in [0, 34] {
        let f = flow(GAME_ACK_DELAY_US, 50_000, jittery(loss), 20);
        eprintln!(
            "loss {loss}/1000: client {} datagrams for {} inputs, {} ack-only | server {} for {} snapshots, {} ack-only",
            f.client.packets_sent, f.inputs, f.client.ack_only_sent,
            f.server.packets_sent, f.snapshots, f.server.ack_only_sent,
        );
        assert_eq!(f.client.ack_only_sent, 0, "loss {loss}");
        assert_eq!(f.server.ack_only_sent, 0, "loss {loss}");
        // unreliable messages: a datagram per flush and nothing else, in both directions
        assert_eq!(f.client.packets_sent, f.inputs, "loss {loss}");
        assert_eq!(f.server.packets_sent, f.snapshots, "loss {loss}");
        // and the acknowledgements did arrive: RTT is measured, packets are not all "lost"
        assert!(f.client.rtt_us > 0 && f.server.rtt_us > 0);
        assert!(
            f.server.packets_lost * 10 < f.snapshots,
            "loss {loss}: {:?}",
            f.server
        );
    }
}

#[test]
fn standalone_acknowledgements_are_bounded_by_the_ack_delay() {
    // for any input rate and delay: at most one ack-only datagram per max_ack_delay; and none at
    // all once the delay is longer than the gaps of the flow they could ride on
    for input_period in [20_000u64, 50_000, 100_000] {
        for delay in [20_000u64, 40_000, 60_000, 100_000, 150_000] {
            let f = flow(delay, input_period, jittery(0), 10);
            for (who, s) in [("client", &f.client), ("server", &f.server)] {
                assert!(
                    s.ack_only_sent <= 10_000_000 / delay + 1,
                    "{who}: {} ack-only with delay {delay}, inputs every {input_period}",
                    s.ack_only_sent
                );
            }
            // the server's acknowledgements ride on its own 20 ms tick, the client's on its inputs
            if delay > 20_000 {
                assert_eq!(
                    f.server.ack_only_sent, 0,
                    "delay {delay}, inputs every {input_period}"
                );
            }
            if delay > input_period {
                assert_eq!(
                    f.client.ack_only_sent, 0,
                    "delay {delay}, inputs every {input_period}"
                );
            }
        }
    }
}

#[test]
#[ignore = "exploration: prints the datagram table"]
fn explore_ack_only_share() {
    for input_period in [20_000u64, 50_000] {
        for delay in [0u64, 20_000, 40_000, 60_000, 100_000] {
            let f = flow(delay, input_period, jittery(0), 20);
            let (a, b) = (f.client, f.server);
            println!(
                "inputs every {:2} ms, max_ack_delay {:3} ms: client sent {:3.0}/s ack-only {:3.0}/s | server sent {:3.0}/s ack-only {:3.0}/s",
                input_period / 1000, delay / 1000,
                a.packets_sent as f64 / 20.0, a.ack_only_sent as f64 / 20.0,
                b.packets_sent as f64 / 20.0, b.ack_only_sent as f64 / 20.0,
            );
        }
    }
}
