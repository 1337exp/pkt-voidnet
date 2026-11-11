//! Rough speed of the core in the simulator. Not a pass/fail test: run it in release mode,
//!   cargo test --release -p voidnet-sim --test bench -- --ignored --nocapture
//! The numbers include the simulator itself (link queues, copies), so they are a pessimistic
//! bound for the core alone.
//! Грубая скорость ядра в симуляторе. Это не проверка, а замер: запускать в release.

use std::time::Instant;
use voidnet_core::wire::ChannelMode;
use voidnet_core::{Addr, ChannelTable, ClientConfig, ConnId, Event, ServerConfig};
use voidnet_sim::world::World;
use voidnet_sim::Params;

fn channels() -> ChannelTable {
    ChannelTable::new(&[
        ChannelMode::ReliableOrdered,
        ChannelMode::Unreliable,
        ChannelMode::UnreliableSequenced,
    ])
    .unwrap()
}

#[test]
#[ignore]
fn sixty_four_clients_at_fifty_hertz() {
    let mut cfg = ServerConfig::new(1, channels());
    cfg.max_per_source = usize::MAX;
    cfg.max_pending_per_source = usize::MAX;
    cfg.hello_burst = 200;
    cfg.global_burst = 2000;
    let mut w: World<64, 256, 160> = World::new(cfg, 1);
    for i in 0..64u8 {
        let addr = Addr::from_ipv4([10, 1, 0, i], 5000 + u16::from(i));
        w.add_client(
            addr,
            ClientConfig::new(1, channels()),
            Params {
                latency_us: 20_000,
                ..Params::default()
            },
        );
    }
    assert!(w.run_until(10_000_000, |w| w.connected_events() == 64));
    let conns: Vec<ConnId> = w
        .server_events
        .iter()
        .filter_map(|e| match e {
            Event::Connected { conn, .. } => Some(*conn),
            _ => None,
        })
        .collect();
    // a snapshot-like message of 400 bytes to everyone, an input-like one of 30 bytes back, 50 Hz
    let (snap, input) = ([7u8; 400], [9u8; 30]);
    let mut buf = [0u8; 1500];
    let seconds = 20u64;
    let before = *w.server.stats();
    let t = Instant::now();
    for _ in 0..seconds * 50 {
        for (i, c) in conns.iter().enumerate() {
            w.server.send(*c, 1, &snap).unwrap();
            w.peers[i].client.send(1, &input).unwrap();
        }
        w.run_for(20_000);
        while w.server.poll_recv(&mut buf).is_some() {}
        for p in &mut w.peers {
            while p.client.poll_recv(&mut buf).is_some() {}
        }
    }
    let wall = t.elapsed();
    let after = *w.server.stats();
    let datagrams_in = after.datagrams - before.datagrams;
    let datagrams_out = (after.bytes_out - before.bytes_out) as f64 / 400.0; // rough: mostly snapshots
    let ticks = seconds * 1000;
    eprintln!("64 clients, 50 Hz both ways, {seconds} virtual seconds");
    eprintln!(
        "wall time           {:.0} ms ({:.2} ms per virtual second)",
        wall.as_secs_f64() * 1e3,
        wall.as_secs_f64() * 1e3 / seconds as f64
    );
    eprintln!(
        "server received     {datagrams_in} datagrams ({:.0} per second)",
        datagrams_in as f64 / seconds as f64
    );
    eprintln!(
        "server sent         ~{datagrams_out:.0} datagrams, {} bytes ({:.1} Mbit/s)",
        after.bytes_out - before.bytes_out,
        (after.bytes_out - before.bytes_out) as f64 * 8.0 / seconds as f64 / 1e6
    );
    eprintln!("whole simulation costs {:.1} microseconds per simulated millisecond, clients and links included", wall.as_secs_f64() * 1e6 / ticks as f64);
    eprintln!(
        "per datagram (server in + out, clients, links): {:.2} microseconds",
        wall.as_secs_f64() * 1e6 / (datagrams_in as f64 * 2.0)
    );
}
