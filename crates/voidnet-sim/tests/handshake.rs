//! Stage 2: handshake and admission, run on the real state machines over the simulator.
//! Этап 2: рукопожатие и допуск на настоящих автоматах поверх имитатора.

use voidnet_core::wire::{self, reject_code, ChannelMode, Datagram, HelloFields, MAX_DATAGRAM};
use voidnet_core::{
    Addr, Blob, ChannelTable, Client, ClientConfig, ClientEvent, Closed, Event, Failed, Server,
    ServerConfig,
};
use voidnet_sim::world::World;
use voidnet_sim::{Params, Pcg32};

const PID: u64 = 0x5445_4501;

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
    c.accept_blob = Blob::new(b"tick=50").unwrap();
    c
}

fn client_cfg() -> ClientConfig {
    ClientConfig::new(PID, channels())
}

fn ip(a: u8, b: u8, port: u16) -> Addr {
    Addr::from_ipv4([10, 0, a, b], port)
}

fn clean() -> Params {
    Params {
        latency_us: 10_000,
        ..Params::default()
    }
}

fn lossy() -> Params {
    Params {
        latency_us: 20_000,
        jitter_us: 8_000,
        loss_permille: 200,
        dup_permille: 100,
        reorder_permille: 100,
        reorder_delay_us: 40_000,
        ..Params::default()
    }
}

type Small = World<8, 64, 32>;

fn hello_fields(cfg: &ServerConfig, rnd: u64) -> HelloFields {
    HelloFields {
        wire_version: 1,
        protocol_id: cfg.protocol_id,
        app_version: 0,
        config_hash: cfg.config_hash(),
        client_random: rnd,
        caps: 0,
    }
}

fn bytes_hello(h: &HelloFields) -> Vec<u8> {
    let mut b = [0u8; MAX_DATAGRAM];
    let n = wire::write_hello(&mut b, h).unwrap();
    b[..n].to_vec()
}

fn bytes_response(coarse: u32, cookie: u64, h: &HelloFields) -> Vec<u8> {
    let mut b = [0u8; MAX_DATAGRAM];
    let n = wire::write_response(&mut b, coarse, cookie, h).unwrap();
    b[..n].to_vec()
}

/// A bare server driven by hand. / Голый сервер, управляемый вручную.
struct Raw {
    srv: Server<8, 32, 32>,
    cfg: ServerConfig,
}

impl Raw {
    fn new(cfg: ServerConfig) -> Self {
        let seed: [u8; 32] = core::array::from_fn(|i| (i * 5 + 1) as u8);
        Self {
            srv: Server::new(cfg, seed, 1_000_000_000),
            cfg,
        }
    }

    /// Send a datagram and collect everything the server wants to send in return.
    fn ask(&mut self, from: &Addr, data: &[u8], now: u64) -> Vec<(Addr, Vec<u8>)> {
        self.srv.handle_datagram(from, data, now);
        let mut out = Vec::new();
        let mut buf = [0u8; MAX_DATAGRAM];
        while let Some((to, n)) = self.srv.poll_transmit(&mut buf, now) {
            out.push((to, buf[..n].to_vec()));
        }
        out
    }

    /// Run hello and return the cookie, if the server answered with a challenge.
    fn challenge(&mut self, from: &Addr, rnd: u64, now: u64) -> Option<(u32, u64)> {
        let h = hello_fields(&self.cfg, rnd);
        let r = self.ask(from, &bytes_hello(&h), now);
        let (_, b) = r.first()?;
        match wire::parse(b, self.cfg.channels.as_slice()) {
            Ok(Datagram::Challenge { coarse, cookie }) => Some((coarse, cookie)),
            _ => None,
        }
    }
}

// ------------------------------------------------------------------ happy path

#[test]
fn connects_and_both_sides_agree() {
    let mut w = Small::new(server_cfg(), 1);
    let me = ip(1, 1, 5000);
    w.add_client(me, client_cfg(), clean());
    assert!(w.run_until(2_000_000, |w| w.client_connected(0)
        && w.connected_events() == 1));

    let Some(ClientEvent::Connected { blob, caps }) = w.peers[0].events.first().copied() else {
        panic!("client saw {:?}", w.peers[0].events)
    };
    assert_eq!((blob.as_bytes(), caps), (&b"tick=50"[..], 0));
    let Some(Event::Connected { conn, addr }) = w.server_events.first().copied() else {
        panic!("server saw {:?}", w.server_events)
    };
    assert_eq!(addr, me);
    assert_eq!(w.server.conn_addr(conn), Some(me));
    assert_eq!(w.server.slots_in_use(), 1);
    assert_eq!(w.server.stats().events_lost, 0);
}

#[test]
fn handshake_completes_over_a_hostile_link() {
    // 20% loss, 10% duplication, 10% reordering, both directions, 100 different seeds
    for seed in 0..100u64 {
        let mut w = Small::new(server_cfg(), seed);
        w.add_client(ip(2, 2, 6000), client_cfg(), lossy());
        let ok = w.run_until(10_000_000, |w| {
            w.client_connected(0) && w.connected_events() == 1
        });
        assert!(
            ok,
            "seed {seed}: events {:?} / {:?}",
            w.peers[0].events, w.server_events
        );
        assert_eq!(
            w.connected_events(),
            1,
            "seed {seed}: exactly one connection"
        );
        assert_eq!(w.server.slots_in_use(), 1, "seed {seed}");
    }
}

// ------------------------------------------------------------------ I1, I2: unverified traffic

/// A pool of hostile datagrams: valid hellos, hellos with wrong fields, responses with a random
/// cookie, data for nobody, random bytes.
fn hostile(rng: &mut Pcg32, cfg: &ServerConfig, now: u64) -> Vec<u8> {
    let h = hello_fields(cfg, rng.next_u64());
    match rng.below(6) {
        0 | 1 => bytes_hello(&h),
        2 => {
            let mut bad = h;
            bad.protocol_id ^= 1;
            bytes_hello(&bad)
        }
        3 => {
            // half with the current server time (so the cookie itself is what fails), half random
            let coarse = if rng.chance(500) {
                (now / 1_000_000) as u32
            } else {
                rng.next_u32()
            };
            bytes_response(coarse, rng.next_u64(), &h)
        }
        4 => {
            let mut v = vec![0u8; 12 + rng.below(100) as usize];
            for b in &mut v {
                *b = rng.next_u32() as u8;
            }
            v[0] = 0;
            v
        }
        _ => (0..rng.below(120)).map(|_| rng.next_u32() as u8).collect(),
    }
}

fn flood(cfg: ServerConfig, label: &str) {
    let mut raw = Raw::new(cfg);
    let mut rng = Pcg32::new(77, 5);
    // 3000 different spoofed sources
    let pool: Vec<Addr> = (0..3000u32)
        .map(|i| Addr::from_ipv4([(i >> 8) as u8 + 20, i as u8, 7, 7], 1000 + (i % 50) as u16))
        .collect();
    let (mut total_in, mut total_out, mut replies) = (0u64, 0u64, 0u64);
    for i in 0..200_000u64 {
        let from = pool[rng.below(pool.len() as u32) as usize];
        let now = 1_000_000_000 + i * 50; // 20k datagrams per second
        let data = hostile(&mut rng, &cfg, now);
        let out = raw.ask(&from, &data, now);
        // I1: nothing sent to an unverified address is longer than what caused it
        assert!(
            out.len() <= 1,
            "{label}: one datagram caused {} replies",
            out.len()
        );
        for (_, b) in &out {
            assert!(
                b.len() <= data.len(),
                "{label}: reply {} longer than request {}",
                b.len(),
                data.len()
            );
            total_out += b.len() as u64;
            replies += 1;
        }
        total_in += data.len() as u64;
    }
    assert!(
        total_out <= total_in,
        "{label}: out {total_out} in {total_in}"
    );
    // I2: no state came out of it
    assert_eq!(raw.srv.slots_in_use(), 0, "{label}");
    assert!(raw.srv.poll_event().is_none(), "{label}");
    assert_eq!(raw.srv.stats().accepted, 0, "{label}");
    assert!(
        raw.srv.stats().bad_cookie > 0,
        "{label}: forged cookies must have been seen"
    );
    assert!(
        raw.srv.stats().stale_cookie > 0,
        "{label}: stale cookies must have been seen"
    );
    eprintln!(
        "{label}: in {total_in} B, out {total_out} B, replies {replies}, stats {:?}",
        raw.srv.stats()
    );
}

#[test]
fn flood_of_hostile_datagrams_gets_no_amplification_and_no_state() {
    flood(server_cfg(), "default limits");
    let mut open = server_cfg();
    open.hello_rate_per_s = 0;
    open.global_rate_per_s = 0;
    flood(open, "limits off");
}

#[test]
fn one_source_cannot_use_more_than_its_bucket() {
    let mut raw = Raw::new(server_cfg());
    let src = ip(9, 9, 1111);
    let mut challenges = 0;
    for i in 0..1000u64 {
        // all within the same millisecond
        let h = hello_fields(&raw.cfg, i);
        let r = raw.ask(&src, &bytes_hello(&h), 1_000_000_000);
        challenges += r.len();
    }
    assert_eq!(
        challenges, 10,
        "burst of 10, nothing more at the same instant"
    );
    assert_eq!(raw.srv.stats().rate_limited_source, 990);
}

#[test]
fn many_spoofed_sources_are_bounded_by_the_global_bucket() {
    let mut raw = Raw::new(server_cfg());
    let mut challenges = 0;
    for i in 0..20_000u32 {
        let src = Addr::from_ipv4([30 + (i >> 16) as u8, (i >> 8) as u8, i as u8, 1], 40000);
        let h = hello_fields(&raw.cfg, u64::from(i));
        challenges += raw.ask(&src, &bytes_hello(&h), 1_000_000_000).len();
    }
    assert_eq!(challenges, 500, "global burst of 500 at one instant");
    assert!(raw.srv.stats().rate_limited_global >= 19_000);
    assert_eq!(raw.srv.slots_in_use(), 0);
}

// ------------------------------------------------------------------ cookies

#[test]
fn cookie_is_bound_to_address_time_fields_and_secret() {
    let mut raw = Raw::new(server_cfg());
    let t0 = 1_000_000_000u64;
    let a = ip(1, 1, 5000);
    let b = ip(1, 2, 5000);
    let h = hello_fields(&raw.cfg, 0xABCD);
    let (coarse, cookie) = raw.challenge(&a, 0xABCD, t0).expect("challenge");

    // forged cookie, other address, other client_random, other coarse: nothing
    for (who, data) in [
        (a, bytes_response(coarse, cookie ^ 1, &h)),
        (b, bytes_response(coarse, cookie, &h)),
        (
            a,
            bytes_response(coarse, cookie, &hello_fields(&raw.cfg, 0xABCE)),
        ),
        (a, bytes_response(coarse + 1, cookie, &h)),
    ] {
        assert!(raw.ask(&who, &data, t0).is_empty());
    }
    assert_eq!(raw.srv.slots_in_use(), 0);
    assert_eq!(raw.srv.stats().bad_cookie, 4);

    // the genuine response works, and repeating it is idempotent
    let ok = bytes_response(coarse, cookie, &h);
    let first = raw.ask(&a, &ok, t0);
    let again = raw.ask(&a, &ok, t0 + 1000);
    assert_eq!(first.len(), 1);
    assert_eq!(first, again, "the same ACCEPT, same token");
    assert_eq!(raw.srv.slots_in_use(), 1);
    assert_eq!(raw.srv.stats().reaccepted, 1);
}

#[test]
fn stale_cookie_is_refused() {
    let mut raw = Raw::new(server_cfg());
    let t0 = 1_000_000_000u64;
    let a = ip(1, 1, 5000);
    let h = hello_fields(&raw.cfg, 5);
    let (coarse, cookie) = raw.challenge(&a, 5, t0).unwrap();
    let resp = bytes_response(coarse, cookie, &h);
    assert!(
        raw.ask(&a, &resp, t0 + 6_000_000).is_empty(),
        "6 s later is stale"
    );
    assert_eq!(raw.srv.stats().stale_cookie, 1);
    assert_eq!(raw.srv.slots_in_use(), 0);
    assert_eq!(
        raw.ask(&a, &resp, t0 + 4_000_000).len(),
        1,
        "4 s later is fresh"
    );
}

#[test]
fn cookie_survives_one_rotation_but_not_two() {
    let mut raw = Raw::new(server_cfg());
    let t0 = 1_000_000_000u64;
    let h1 = hello_fields(&raw.cfg, 1);
    let a = ip(1, 1, 5000);
    let (c1, k1) = raw.challenge(&a, 1, t0).unwrap();
    raw.srv.rotate_secret([7; 16], t0 + 100);
    assert_eq!(
        raw.ask(&a, &bytes_response(c1, k1, &h1), t0 + 200).len(),
        1,
        "previous secret still counts"
    );

    let h2 = hello_fields(&raw.cfg, 2);
    let b = ip(1, 2, 5000);
    let (c2, k2) = raw.challenge(&b, 2, t0 + 300).unwrap();
    raw.srv.rotate_secret([8; 16], t0 + 400);
    raw.srv.rotate_secret([9; 16], t0 + 500);
    assert!(
        raw.ask(&b, &bytes_response(c2, k2, &h2), t0 + 600)
            .is_empty(),
        "two rotations old"
    );
}

// ------------------------------------------------------------------ table limits

#[test]
fn a_full_server_says_so() {
    let mut w = Small::new(server_cfg(), 3);
    for i in 0..12u8 {
        w.add_client(ip(i, 1, 5000), client_cfg(), clean());
    }
    w.run_for(5_000_000);
    assert_eq!(w.server.slots_in_use(), 8);
    assert_eq!(w.connected_events(), 8);
    let full = w
        .peers
        .iter()
        .filter(|p| {
            p.events
                .contains(&ClientEvent::Failed(Failed::Rejected(reject_code::FULL)))
        })
        .count();
    assert_eq!(full, 4, "the other four were told the server is full");
}

#[test]
fn one_source_cannot_take_every_slot() {
    let mut cfg = server_cfg();
    cfg.max_per_source = 3;
    let mut w = Small::new(cfg, 4);
    for port in 0..6u16 {
        w.add_client(ip(5, 5, 7000 + port), client_cfg(), clean());
    }
    w.run_for(5_000_000);
    assert_eq!(w.connected_events(), 3);
    let limited = w
        .peers
        .iter()
        .filter(|p| {
            p.events.contains(&ClientEvent::Failed(Failed::Rejected(
                reject_code::SOURCE_LIMIT,
            )))
        })
        .count();
    assert_eq!(limited, 3);
    // somebody else is not affected
    w.add_client(ip(6, 6, 7000), client_cfg(), clean());
    assert!(w.run_until(3_000_000, |w| w.connected_events() == 4));
}

#[test]
fn max_connections_below_the_table_size_is_respected() {
    let mut cfg = server_cfg();
    cfg.max_connections = 2;
    let mut w = Small::new(cfg, 5);
    for i in 0..5u8 {
        w.add_client(ip(i, 9, 5000), client_cfg(), clean());
    }
    w.run_for(4_000_000);
    assert_eq!(w.server.slots_in_use(), 2);
}

#[test]
fn pending_connection_expires_without_a_trace() {
    let mut raw = Raw::new(server_cfg());
    let t0 = 1_000_000_000u64;
    let a = ip(1, 1, 5000);
    let h = hello_fields(&raw.cfg, 5);
    let (coarse, cookie) = raw.challenge(&a, 5, t0).unwrap();
    assert_eq!(
        raw.ask(&a, &bytes_response(coarse, cookie, &h), t0).len(),
        1
    );
    assert_eq!(raw.srv.slots_in_use(), 1);
    raw.srv.handle_timeout(t0 + 4_000_000);
    assert_eq!(raw.srv.slots_in_use(), 1);
    raw.srv.handle_timeout(t0 + 5_000_001);
    assert_eq!(raw.srv.slots_in_use(), 0);
    assert!(raw.srv.poll_event().is_none(), "the host never heard of it");
    assert_eq!(raw.srv.stats().unconfirmed_expired, 1);
}

// ------------------------------------------------------------------ lifecycle

#[test]
fn reconnect_from_the_same_address_replaces_the_old_connection() {
    let mut w = Small::new(server_cfg(), 6);
    w.add_client(ip(1, 1, 5000), client_cfg(), clean());
    assert!(w.run_until(2_000_000, |w| w.connected_events() == 1));
    let Event::Connected { conn: old, .. } = w.server_events[0] else {
        panic!()
    };

    w.restart_client(0, client_cfg());
    assert!(w.run_until(3_000_000, |w| w.connected_events() == 2));
    assert_eq!(w.server.slots_in_use(), 1);
    assert!(w.server_events.contains(&Event::Disconnected {
        conn: old,
        reason: Closed::Replaced
    }));
    let Some(Event::Connected { conn: new, .. }) = w
        .server_events
        .iter()
        .rev()
        .find(|e| matches!(e, Event::Connected { .. }))
        .copied()
    else {
        panic!()
    };
    assert_ne!(old, new, "a new handle, even if the slot is the same");
    assert!(!w.server.disconnect(old, 0), "the old handle is stale");
    assert_eq!(w.server.slots_in_use(), 1);
}

#[test]
fn silence_ends_a_connection_on_both_sides() {
    let mut cfg = server_cfg();
    cfg.idle_timeout_us = 3_000_000;
    let mut ccfg = client_cfg();
    ccfg.idle_timeout_us = 3_000_000;
    let mut w = Small::new(cfg, 7);
    w.add_client(ip(1, 1, 5000), ccfg, clean());
    assert!(w.run_until(2_000_000, |w| w.connected_events() == 1));
    // the path goes dark
    w.peers[0].up.params_mut().loss_permille = 1000;
    w.peers[0].down.params_mut().loss_permille = 1000;
    w.run_for(5_000_000);
    assert_eq!(w.server.slots_in_use(), 0);
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
}

#[test]
fn disconnect_reaches_the_other_side_with_its_reason() {
    let mut w = Small::new(server_cfg(), 8);
    w.add_client(ip(1, 1, 5000), client_cfg(), clean());
    w.add_client(ip(2, 2, 5000), client_cfg(), clean());
    assert!(w.run_until(2_000_000, |w| w.connected_events() == 2));

    // the client leaves
    w.peers[0].client.disconnect(5);
    w.run_for(500_000);
    assert!(w.server_events.iter().any(|e| matches!(
        e,
        Event::Disconnected {
            reason: Closed::Remote(5),
            ..
        }
    )));
    assert_eq!(w.server.slots_in_use(), 1);

    // the server throws the other one out
    let conn = w
        .server_events
        .iter()
        .find_map(|e| match e {
            Event::Connected { conn, addr } if *addr == ip(2, 2, 5000) => Some(*conn),
            _ => None,
        })
        .unwrap();
    assert!(w.server.disconnect(conn, 9));
    w.run_for(500_000);
    assert!(w.peers[1]
        .events
        .contains(&ClientEvent::Disconnected(Closed::Remote(9))));
    assert_eq!(w.server.slots_in_use(), 0);
}

#[test]
fn mismatched_versions_and_configs_are_rejected_with_a_code() {
    let mut w = Small::new(server_cfg(), 9);
    let mut wrong_proto = client_cfg();
    wrong_proto.protocol_id ^= 1;
    let other = ChannelTable::new(&[ChannelMode::ReliableOrdered]).unwrap();
    w.add_client(ip(1, 1, 5000), wrong_proto, clean());
    w.add_client(ip(2, 2, 5000), ClientConfig::new(PID, other), clean());
    w.run_for(2_000_000);
    assert!(w.peers[0]
        .events
        .contains(&ClientEvent::Failed(Failed::Rejected(reject_code::VERSION))));
    assert!(w.peers[1]
        .events
        .contains(&ClientEvent::Failed(Failed::Rejected(reject_code::CONFIG))));
    assert_eq!(w.server.slots_in_use(), 0);
}

#[test]
fn a_silent_server_means_timeout() {
    let mut w = Small::new(server_cfg(), 10);
    let mut p = clean();
    p.loss_permille = 1000;
    w.add_client(ip(1, 1, 5000), client_cfg(), p);
    w.run_for(11_000_000);
    assert!(w.peers[0]
        .events
        .contains(&ClientEvent::Failed(Failed::Timeout)));
}

// ------------------------------------------------------------------ forgery and replay

#[test]
fn forged_answers_do_not_move_a_client() {
    let server = Addr::from_ipv4([10, 255, 255, 1], 7000);
    let mut c = Client::new(client_cfg());
    assert!(c.connect(server, 0x1111, 0));
    let mut buf = [0u8; MAX_DATAGRAM];
    c.poll_transmit(&mut buf, 0).unwrap(); // the HELLO
    let mut b = [0u8; MAX_DATAGRAM];

    // REJECT and ACCEPT with the wrong echo, from the right address
    let n = wire::write_reject(&mut b, 3, 0x2222).unwrap();
    c.handle_datagram(&server, &b[..n], 1);
    let n = wire::write_accept(&mut b, 1, 0x2222, 0, b"").unwrap();
    c.handle_datagram(&server, &b[..n], 1);
    // the right datagrams from the wrong address
    let other = Addr::from_ipv4([6, 6, 6, 6], 7000);
    let n = wire::write_reject(&mut b, 3, 0x1111).unwrap();
    c.handle_datagram(&other, &b[..n], 1);
    let n = wire::write_accept(&mut b, 1, 0x1111, 0, b"").unwrap();
    c.handle_datagram(&other, &b[..n], 1);
    assert!(!c.is_connected());
    assert!(c.poll_event().is_none());

    // the genuine ACCEPT works
    let n = wire::write_accept(&mut b, 0xFEED, 0x1111, 0, b"hi").unwrap();
    c.handle_datagram(&server, &b[..n], 2);
    assert!(c.is_connected());
    // a later forged DISCONNECT without the token does nothing
    let ch = channels();
    let mut w = wire::DataWriter::new(&mut buf, ch.as_slice(), 0xBAD, 1).unwrap();
    w.disconnect(1).unwrap();
    let n = w.finish().unwrap();
    c.handle_datagram(&server, &buf[..n], 3);
    assert!(c.is_connected());
}

#[test]
fn replayed_and_forged_datagrams_change_nothing_on_the_server() {
    let mut w = Small::new(server_cfg(), 11);
    let me = ip(1, 1, 5000);
    w.add_client(me, client_cfg(), clean());
    // record every datagram the client sends
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for _ in 0..1500 {
        // snoop on the up link before the server reads it
        w.step();
    }
    assert_eq!(w.connected_events(), 1);
    // build the datagrams an attacker could capture: the client's own handshake bytes
    let h = HelloFields {
        wire_version: 1,
        protocol_id: PID,
        app_version: 0,
        config_hash: server_cfg().config_hash(),
        client_random: 0,
        caps: 0,
    };
    seen.push(bytes_hello(&h));

    let before = (w.server.slots_in_use(), w.connected_events());
    let other = ip(66, 6, 6666);
    // data from an unknown address, and with a wrong token from the right one
    let mut buf = [0u8; MAX_DATAGRAM];
    let ch = channels();
    let mut dw = wire::DataWriter::new(&mut buf, ch.as_slice(), 0x1234, 7).unwrap();
    dw.disconnect(1).unwrap();
    let n = dw.finish().unwrap();
    let forged = buf[..n].to_vec();
    w.inject(&other, &forged);
    w.inject(&me, &forged);
    for s in &seen {
        w.inject(&other, s);
    }
    assert_eq!((w.server.slots_in_use(), w.connected_events()), before);
    assert_eq!(w.server.stats().unknown_peer, 1);
    assert_eq!(w.server.stats().bad_token, 1);
    w.run_for(100_000);
    assert!(w.client_connected(0));
}

// ------------------------------------------------------------------ events are never lost

#[test]
fn events_are_never_lost_and_admission_waits_for_the_host() {
    // E = 16 holds 2 events for each of 4 slots plus 2
    let mut w: World<4, 32, 16> = World::new(server_cfg(), 12);
    w.drain_events = false;
    let mut connected = 0;
    for round in 0..30u8 {
        let i = w.add_client(ip(round, 3, 5000), client_cfg(), clean());
        w.run_for(300_000);
        if w.client_connected(i) {
            connected += 1;
            w.peers[i].client.disconnect(0);
            w.run_for(100_000);
        }
    }
    assert_eq!(w.server.stats().events_lost, 0, "never lost");
    assert!(
        connected > 0 && connected < 30,
        "the undrained queue must stop admission: {connected}"
    );

    // the host drains: service resumes
    while w.server.poll_event().is_some() {}
    let i = w.add_client(ip(250, 3, 5000), client_cfg(), clean());
    w.run_for(500_000);
    assert!(w.client_connected(i));
    assert_eq!(w.server.stats().events_lost, 0);
}

// ------------------------------------------------------------------ determinism

#[test]
fn a_whole_scenario_is_reproducible_from_its_seed() {
    let run = |seed: u64| {
        let mut w = Small::new(server_cfg(), seed);
        for i in 0..5u8 {
            w.add_client(ip(i, 7, 5000), client_cfg(), lossy());
        }
        w.run_for(6_000_000);
        (w.trace(), w.connected_events(), *w.server.stats())
    };
    assert_eq!(run(5), run(5));
    assert_ne!(run(5).0, run(6).0);
    // golden: if this changes, behaviour changed (and it must be the same on every OS)
    let (hash, connected, _) = run(5);
    assert_eq!(connected, 5);
    assert_eq!(hash, 0xf947_d65d_c607_ff5d, "golden trace: {hash:#018x}");
}

// ------------------------------------------------------------------ gaps found by mutation testing

#[test]
fn a_full_server_refuses_at_the_first_hello() {
    let mut cfg = server_cfg();
    cfg.max_connections = 1;
    let mut raw = Raw::new(cfg);
    let t0 = 1_000_000_000u64;
    let a = ip(1, 1, 5000);
    let h = hello_fields(&raw.cfg, 1);
    let (coarse, cookie) = raw.challenge(&a, 1, t0).unwrap();
    assert_eq!(
        raw.ask(&a, &bytes_response(coarse, cookie, &h), t0).len(),
        1
    );
    // the only slot is taken: a second client is told at once, without a cookie round trip
    let b = ip(2, 2, 5000);
    let r = raw.ask(&b, &bytes_hello(&hello_fields(&raw.cfg, 2)), t0);
    assert_eq!(r.len(), 1);
    assert!(matches!(
        wire::parse(&r[0].1, raw.cfg.channels.as_slice()),
        Ok(Datagram::Reject {
            code: reject_code::FULL,
            echo: 2
        })
    ));
}

#[test]
fn the_hello_limit_counts_the_source_not_the_port() {
    let mut raw = Raw::new(server_cfg());
    let mut challenges = 0;
    for port in 0..1000u16 {
        let src = ip(8, 8, 2000 + port); // one IP, a new port every time
        let h = hello_fields(&raw.cfg, u64::from(port));
        challenges += raw.ask(&src, &bytes_hello(&h), 1_000_000_000).len();
    }
    assert_eq!(challenges, 10, "ports do not buy more tokens");
}

#[test]
fn app_version_is_enforced_only_when_the_server_sets_one() {
    let mut strict = server_cfg();
    strict.app_version = 3;
    let mut w = Small::new(strict, 13);
    let mut v3 = client_cfg();
    v3.app_version = 3;
    let mut v4 = client_cfg();
    v4.app_version = 4;
    w.add_client(ip(1, 1, 5000), v3, clean());
    w.add_client(ip(2, 2, 5000), v4, clean());
    w.run_for(2_000_000);
    assert!(w.client_connected(0));
    assert!(w.peers[1]
        .events
        .contains(&ClientEvent::Failed(Failed::Rejected(reject_code::VERSION))));

    // a server without an app version takes any
    let mut w = Small::new(server_cfg(), 14);
    w.add_client(ip(1, 1, 5000), v4, clean());
    w.run_for(2_000_000);
    assert!(w.client_connected(0));
}

#[test]
fn a_client_recovers_from_a_forged_challenge() {
    let mut w = Small::new(server_cfg(), 15);
    w.add_client(ip(1, 1, 5000), client_cfg(), clean());
    // an off-path attacker answers the HELLO with a CHALLENGE of its own before the server does
    let server = w.server_addr();
    let mut b = [0u8; MAX_DATAGRAM];
    let now = w.now;
    let n = wire::write_challenge(&mut b, (now / 1_000_000) as u32, 0xDEAD_BEEF).unwrap();
    w.peers[0].client.handle_datagram(&server, &b[..n], now);
    // the client sends RESPONSEs with a cookie the server will not accept, then starts over
    assert!(w.run_until(9_000_000, |w| w.client_connected(0)
        && w.connected_events() == 1));
    assert!(w.server.stats().bad_cookie >= 1);
}
