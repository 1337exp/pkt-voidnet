//! Stage 3 end to end: real handshake, then messages in all three modes, both directions,
//! several clients at once, over hostile links.
//! Этап 3 целиком: настоящее рукопожатие, затем сообщения во всех трёх режимах, в обе стороны,
//! несколько клиентов, враждебные каналы.

use std::collections::HashMap;
use voidnet_core::conn::SendError;
use voidnet_core::wire::ChannelMode;
use voidnet_core::{
    Addr, ChannelTable, ClientConfig, ClientEvent, Closed, ConnId, Event, ServerConfig,
};
use voidnet_sim::world::World;
use voidnet_sim::Params;

const PID: u64 = 0x5445_4501;
const RELIABLE: u8 = 0;
const UNRELIABLE: u8 = 1;
const SEQUENCED: u8 = 2;

type Big = World<16, 64, 40>;

fn channels() -> ChannelTable {
    ChannelTable::new(&[
        ChannelMode::ReliableOrdered,
        ChannelMode::Unreliable,
        ChannelMode::UnreliableSequenced,
    ])
    .unwrap()
}

fn server_cfg() -> ServerConfig {
    let mut c = ServerConfig::new(PID, channels());
    c.max_per_source = usize::MAX;
    c.max_pending_per_source = usize::MAX;
    c.hello_burst = 100;
    c
}

fn client_cfg() -> ClientConfig {
    ClientConfig::new(PID, channels())
}

fn ip(i: u8) -> Addr {
    Addr::from_ipv4([10, 0, 1, i], 5000 + u16::from(i))
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
        loss_permille: 150,
        dup_permille: 80,
        reorder_permille: 100,
        reorder_delay_us: 40_000,
        ..Params::default()
    }
}

fn conn_of(w: &Big, addr: Addr) -> Option<ConnId> {
    w.server_events.iter().rev().find_map(|e| match e {
        Event::Connected { conn, addr: a } if *a == addr => Some(*conn),
        _ => None,
    })
}

fn msg(from: u32, i: u32) -> Vec<u8> {
    let mut v = vec![0u8; 8 + (i as usize * 37) % 300];
    v[..4].copy_from_slice(&from.to_le_bytes());
    v[4..8].copy_from_slice(&i.to_le_bytes());
    for (k, b) in v.iter_mut().enumerate().skip(8) {
        *b = (k as u32 ^ from ^ i) as u8;
    }
    v
}

fn parse(data: &[u8]) -> (u32, u32) {
    let from = u32::from_le_bytes(data[..4].try_into().unwrap());
    let i = u32::from_le_bytes(data[4..8].try_into().unwrap());
    for (k, b) in data.iter().enumerate().skip(8) {
        assert_eq!(
            *b,
            (k as u32 ^ from ^ i) as u8,
            "corrupted message {from}/{i}"
        );
    }
    (from, i)
}

#[test]
fn eight_clients_exchange_ordered_streams_both_ways_over_hostile_links() {
    let mut w = Big::new(server_cfg(), 21);
    let n = 8u8;
    for i in 0..n {
        w.add_client(ip(i), client_cfg(), hostile());
    }
    assert!(w.run_until(15_000_000, |w| w.connected_events() == 8
        && (0..8).all(|i| w.client_connected(i))));
    let conns: Vec<ConnId> = (0..n).map(|i| conn_of(&w, ip(i)).unwrap()).collect();

    let total = 120u32;
    let (mut to_srv, mut to_cli) = (vec![0u32; 8], vec![0u32; 8]);
    let mut got_srv: Vec<Vec<u32>> = vec![Vec::new(); 8];
    let mut got_cli: Vec<Vec<u32>> = vec![Vec::new(); 8];
    let mut buf = [0u8; 1500];
    let ok = w.run_until(180_000_000, |w| {
        for i in 0..8usize {
            while to_cli[i] < total
                && w.server
                    .send(conns[i], RELIABLE, &msg(1000 + i as u32, to_cli[i]))
                    .is_ok()
            {
                to_cli[i] += 1;
            }
            while to_srv[i] < total
                && w.peers[i]
                    .client
                    .send(RELIABLE, &msg(i as u32, to_srv[i]))
                    .is_ok()
            {
                to_srv[i] += 1;
            }
            w.server.flush(conns[i]).unwrap();
            w.peers[i].client.flush().unwrap();
            while let Some((ch, len)) = w.peers[i].client.poll_recv(&mut buf) {
                assert_eq!(ch, RELIABLE);
                let (from, k) = parse(&buf[..len]);
                assert_eq!(
                    from,
                    1000 + i as u32,
                    "a message for client {i} came from the wrong stream"
                );
                got_cli[i].push(k);
            }
        }
        while let Some(r) = w.server.poll_recv(&mut buf) {
            let (from, k) = parse(&buf[..r.len]);
            let who = conns
                .iter()
                .position(|c| *c == r.conn)
                .expect("known connection");
            assert_eq!(
                from as usize, who,
                "a message from client {who} was attributed to another"
            );
            got_srv[who].push(k);
        }
        got_srv.iter().all(|g| g.len() as u32 == total)
            && got_cli.iter().all(|g| g.len() as u32 == total)
    });
    assert!(
        ok,
        "server got {:?}, clients got {:?}",
        got_srv.iter().map(Vec::len).collect::<Vec<_>>(),
        got_cli.iter().map(Vec::len).collect::<Vec<_>>()
    );
    for i in 0..8 {
        assert!(
            got_srv[i].iter().copied().eq(0..total),
            "client {i} to server: order"
        );
        assert!(
            got_cli[i].iter().copied().eq(0..total),
            "server to client {i}: order"
        );
    }
}

#[test]
fn server_sees_the_round_trip_time_of_every_client() {
    let mut w = Big::new(server_cfg(), 22);
    for i in 0..4u8 {
        // 10, 30, 60 and 120 ms one way
        w.add_client(
            ip(i),
            client_cfg(),
            clean([10_000, 30_000, 60_000, 120_000][usize::from(i)]),
        );
    }
    assert!(w.run_until(5_000_000, |w| w.connected_events() == 4));
    let conns: Vec<ConnId> = (0..4u8).map(|i| conn_of(&w, ip(i)).unwrap()).collect();
    let mut buf = [0u8; 1500];
    // a game-like flow for a few seconds
    for tick in 0..300u32 {
        for (i, c) in conns.iter().enumerate() {
            w.server.send(*c, UNRELIABLE, &msg(i as u32, tick)).unwrap();
            w.server.flush(*c).unwrap();
            w.peers[i]
                .client
                .send(UNRELIABLE, &msg(i as u32, tick))
                .unwrap();
            w.peers[i].client.flush().unwrap();
        }
        w.run_for(20_000);
        for i in 0..4 {
            while w.peers[i].client.poll_recv(&mut buf).is_some() {}
        }
        while w.server.poll_recv(&mut buf).is_some() {}
    }
    for (i, c) in conns.iter().enumerate() {
        let want = [20_000u64, 60_000, 120_000, 240_000][i];
        let s = w.server.conn_stats(*c).unwrap();
        assert!(
            s.rtt_us >= want * 90 / 100 && s.rtt_us <= want * 115 / 100 + 3_000,
            "client {i}: server measured {} us, link is {want} us",
            s.rtt_us
        );
        let cs = w.peers[i].client.conn_stats().unwrap();
        assert!(
            cs.rtt_us >= want * 90 / 100 && cs.rtt_us <= want * 115 / 100 + 3_000,
            "client {i}: client measured {}",
            cs.rtt_us
        );
    }
}

#[test]
fn keepalive_holds_an_idle_connection_open_far_beyond_the_idle_timeout() {
    let mut cfg = server_cfg();
    cfg.idle_timeout_us = 3_000_000;
    let mut ccfg = client_cfg();
    ccfg.idle_timeout_us = 3_000_000;
    let mut w = Big::new(cfg, 23);
    w.add_client(ip(1), ccfg, clean(30_000));
    assert!(w.run_until(3_000_000, |w| w.connected_events() == 1));
    w.run_for(30_000_000); // ten idle timeouts of nothing but keep-alives
    assert!(w.client_connected(0));
    assert_eq!(w.server.slots_in_use(), 1);
    assert!(!w
        .server_events
        .iter()
        .any(|e| matches!(e, Event::Disconnected { .. })));
    let c = conn_of(&w, ip(1)).unwrap();
    assert!(
        w.server.conn_stats(c).unwrap().packets_sent >= 20,
        "the keep-alives are what held it"
    );
}

#[test]
fn a_peer_that_stops_answering_is_dropped_and_the_host_is_told() {
    let mut cfg = server_cfg();
    cfg.idle_timeout_us = 4_000_000;
    let mut ccfg = client_cfg();
    ccfg.idle_timeout_us = 4_000_000;
    let mut w = Big::new(cfg, 24);
    w.add_client(ip(1), ccfg, clean(20_000));
    assert!(w.run_until(3_000_000, |w| w.connected_events() == 1));
    w.run_for(200_000); // the client hears the server's first acknowledgement
    let c = conn_of(&w, ip(1)).unwrap();
    w.peers[0].up.params_mut().loss_permille = 1000;
    w.peers[0].down.params_mut().loss_permille = 1000;
    w.server.send(c, RELIABLE, b"anyone there?").unwrap();
    w.server.flush(c).unwrap();
    w.run_for(10_000_000);
    assert!(w.server_events.iter().any(|e| matches!(
        e,
        Event::Disconnected {
            reason: Closed::Timeout,
            ..
        }
    )));
    assert!(w.peers[0]
        .events
        .contains(&ClientEvent::Disconnected(Closed::Timeout)));
    assert_eq!(
        w.server.send(c, RELIABLE, b"too late"),
        Err(SendError::NotConnected),
        "the handle is stale"
    );
    assert_eq!(w.server.slots_in_use(), 0);
}

#[test]
fn the_first_server_message_is_not_slowed_down_by_confirmation() {
    let mut w = Big::new(server_cfg(), 25);
    w.add_client(ip(1), client_cfg(), clean(40_000)); // 80 ms round trip
    let mut buf = [0u8; 1500];
    let mut sent_at = None;
    let mut got_at = None;
    w.run_until(3_000_000, |w| {
        if sent_at.is_none() {
            if let Some(c) = conn_of(w, ip(1)) {
                w.server.send(c, RELIABLE, b"welcome").unwrap();
                w.server.flush(c).unwrap();
                sent_at = Some(w.now);
            }
        }
        if w.peers[0].client.poll_recv(&mut buf).is_some() {
            got_at = Some(w.now);
        }
        got_at.is_some()
    });
    let (s, g) = (sent_at.unwrap(), got_at.unwrap());
    // from the moment the host knows the client until the client reads the message: one way
    assert!(
        g - s <= 40_000 + 30_000,
        "{} ms after the server could first send",
        (g - s) / 1000
    );
}

#[test]
#[allow(clippy::needless_range_loop)]
fn a_busy_client_does_not_starve_the_others() {
    let mut w = Big::new(server_cfg(), 26);
    let n = 8u8;
    for i in 0..n {
        w.add_client(ip(i), client_cfg(), clean(10_000));
    }
    assert!(w.run_until(5_000_000, |w| w.connected_events() == 8));
    let conns: Vec<ConnId> = (0..n).map(|i| conn_of(&w, ip(i)).unwrap()).collect();
    let mut buf = [0u8; 1500];
    let mut got = [0u32; 8];
    for tick in 0..500u32 {
        // every tick the server queues something for everybody, client 0 gets far more
        for (i, c) in conns.iter().enumerate() {
            let times = if i == 0 { 8 } else { 1 };
            for _ in 0..times {
                let _ = w.server.send(*c, UNRELIABLE, &msg(i as u32, tick));
            }
            w.server.flush(*c).unwrap();
        }
        w.run_for(20_000);
        for i in 0..8usize {
            while w.peers[i].client.poll_recv(&mut buf).is_some() {
                got[i] += 1;
            }
        }
    }
    // the five others got (almost) one message per tick each
    for (i, g) in got.iter().enumerate().skip(1) {
        assert!(*g >= 450, "client {i} got only {g} of 500: starved");
    }
}

#[test]
fn a_stack_of_datagram_costs_stay_game_sized() {
    // 8 clients, 50 Hz both ways: roughly one datagram per message, acknowledgements ride along
    let mut w = Big::new(server_cfg(), 27);
    for i in 0..8u8 {
        w.add_client(ip(i), client_cfg(), clean(20_000));
    }
    assert!(w.run_until(5_000_000, |w| w.connected_events() == 8));
    let conns: Vec<ConnId> = (0..8u8).map(|i| conn_of(&w, ip(i)).unwrap()).collect();
    let before: Vec<_> = conns
        .iter()
        .map(|c| w.server.conn_stats(*c).unwrap())
        .collect();
    let mut buf = [0u8; 1500];
    for tick in 0..500u32 {
        for (i, c) in conns.iter().enumerate() {
            w.server.send(*c, UNRELIABLE, &msg(i as u32, tick)).unwrap();
            w.server.flush(*c).unwrap();
            w.peers[i]
                .client
                .send(UNRELIABLE, &msg(i as u32, tick))
                .unwrap();
            w.peers[i].client.flush().unwrap();
        }
        w.run_for(20_000);
        for i in 0..8usize {
            while w.peers[i].client.poll_recv(&mut buf).is_some() {}
        }
        while w.server.poll_recv(&mut buf).is_some() {}
    }
    for (i, c) in conns.iter().enumerate() {
        let s = w.server.conn_stats(*c).unwrap();
        let sent = s.packets_sent - before[i].packets_sent;
        let ack_only = s.ack_only_sent - before[i].ack_only_sent;
        assert!(
            (480..=560).contains(&sent),
            "client {i}: {sent} datagrams for 500 messages"
        );
        assert!(
            ack_only * 20 < sent,
            "client {i}: {ack_only} ack-only of {sent}"
        );
    }
}

#[test]
fn sequenced_state_is_never_older_than_what_was_already_seen() {
    let mut w = Big::new(server_cfg(), 28);
    w.add_client(ip(1), client_cfg(), hostile());
    assert!(w.run_until(15_000_000, |w| w.connected_events() == 1));
    let c = conn_of(&w, ip(1)).unwrap();
    let mut buf = [0u8; 1500];
    let mut latest: HashMap<u8, u32> = HashMap::new();
    let mut seen = 0;
    for tick in 0..1500u32 {
        w.server.send(c, SEQUENCED, &msg(7, tick)).unwrap();
        w.server.flush(c).unwrap();
        w.run_for(10_000);
        while let Some((ch, len)) = w.peers[0].client.poll_recv(&mut buf) {
            let (_, k) = parse(&buf[..len]);
            if let Some(prev) = latest.insert(ch, k) {
                assert!(k > prev, "state went back from {prev} to {k}");
            }
            seen += 1;
        }
    }
    assert!(seen > 800, "{seen} of 1500 got through a 15% lossy link");
}

#[test]
fn a_limited_send_budget_is_shared_fairly() {
    // the host lets only 4 datagrams leave per tick while 8 clients each want one
    let mut w = Big::new(server_cfg(), 29);
    for i in 0..8u8 {
        w.add_client(ip(i), client_cfg(), clean(10_000));
    }
    assert!(w.run_until(5_000_000, |w| w.connected_events() == 8));
    let conns: Vec<ConnId> = (0..8u8).map(|i| conn_of(&w, ip(i)).unwrap()).collect();
    let before: Vec<u64> = conns
        .iter()
        .map(|c| w.server.conn_stats(*c).unwrap().packets_sent)
        .collect();
    w.server_budget = Some(4);
    let mut buf = [0u8; 1500];
    for tick in 0..1000u32 {
        for (i, c) in conns.iter().enumerate() {
            let _ = w.server.send(*c, UNRELIABLE, &msg(i as u32, tick));
            w.server.flush(*c).unwrap();
        }
        w.run_for(1_000);
        for i in 0..8usize {
            while w.peers[i].client.poll_recv(&mut buf).is_some() {}
        }
    }
    let shares: Vec<u64> = conns
        .iter()
        .zip(&before)
        .map(|(c, b)| w.server.conn_stats(*c).unwrap().packets_sent - b)
        .collect();
    let (min, max) = (*shares.iter().min().unwrap(), *shares.iter().max().unwrap());
    assert!(
        min >= 400 && max <= 600,
        "datagrams per client {shares:?}: the budget must be split about evenly"
    );
}
