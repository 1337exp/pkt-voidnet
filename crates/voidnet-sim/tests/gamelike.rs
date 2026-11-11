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
            let _ = p.b.conn.send(UNRELIABLE, &vec![2u8; lb]);
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
    [(sa.packets_sent, sa.packets_lost, la), (sb.packets_sent, sb.packets_lost, lb)]
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

/// Datagram rate and ack-only share for a two-way stream; a clean link, so loss does not hide it.
#[test]
#[ignore = "exploration: prints datagrams per second and the ack-only share"]
fn explore_ack_only_share() {
    for (name, a_period_us, b_period_us) in [
        ("both 50 Hz", 20_000u64, 20_000u64),
        ("client sends 20/s, server 50/s (standing)", 50_000, 20_000),
    ] {
        let mut p = Pair::new(cfg(), Params { latency_us: 1_000, ..Params::default() }, 3);
        let end = p.now + 20_000_000;
        let (mut na, mut nb) = (p.now, p.now);
        while p.now < end {
            if p.now >= na {
                na += a_period_us;
                let _ = p.a.conn.send(UNRELIABLE, &[1u8; 30]);
            }
            if p.now >= nb {
                nb += b_period_us;
                let _ = p.b.conn.send(UNRELIABLE, &[2u8; 120]);
            }
            p.step();
            while p.a.conn.poll_recv().is_some() {}
            while p.b.conn.poll_recv().is_some() {}
        }
        let (sa, sb) = (p.a.conn.stats(), p.b.conn.stats());
        println!(
            "{name}: a (client) sent {:.0}/s ack-only {:.0}/s | b (server) sent {:.0}/s ack-only {:.0}/s",
            sa.packets_sent as f64 / 20.0, sa.ack_only_sent as f64 / 20.0,
            sb.packets_sent as f64 / 20.0, sb.ack_only_sent as f64 / 20.0,
        );
    }
}
