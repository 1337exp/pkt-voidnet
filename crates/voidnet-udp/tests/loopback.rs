//! The driver on real sockets over the loopback interface: handshake, messages both ways in
//! every delivery mode, the client's own socket thread, and disconnects.
//! Драйвер на настоящих сокетах через loopback: рукопожатие, сообщения в обе стороны во всех
//! режимах доставки, свой поток сокета у клиента и разрывы.

use std::time::{Duration, Instant};

use voidnet_core::{
    ChannelMode, ChannelTable, ClientConfig, ClientEvent, Closed, ConnId, Event, ServerConfig,
};
use voidnet_udp::{UdpClient, UdpServer, RECV_BUF};

type Srv = UdpServer<4, 16, 16>;

const PROTOCOL: u64 = 0x7465_7374_2d75_6470;
const RELIABLE: u8 = 0;
const LOOSE: u8 = 1;

fn channels() -> ChannelTable {
    ChannelTable::new(&[ChannelMode::ReliableOrdered, ChannelMode::Unreliable]).unwrap()
}

fn pair() -> (Srv, UdpClient) {
    let server = Srv::bind("127.0.0.1:0", ServerConfig::new(PROTOCOL, channels())).unwrap();
    let client = UdpClient::connect(
        server.local_addr().unwrap(),
        ClientConfig::new(PROTOCOL, channels()),
    )
    .unwrap();
    (server, client)
}

/// Pump both ends until `done` or two seconds pass. / Качать обе стороны до `done` или 2 с.
fn run(server: &mut Srv, client: &mut UdpClient, mut done: impl FnMut(&mut Srv, &mut UdpClient) -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(2);
    while Instant::now() < end {
        client.pump(None).unwrap();
        server.pump(Some(Duration::from_millis(1))).unwrap();
        if done(server, client) {
            return true;
        }
    }
    false
}

fn connect(server: &mut Srv, client: &mut UdpClient) -> ConnId {
    let mut conn = None;
    let mut client_saw = false;
    assert!(run(server, client, |s, c| {
        while let Some(e) = s.poll_event() {
            if let Event::Connected { conn: id, .. } = e {
                conn = Some(id);
            }
        }
        while let Some(e) = c.poll_event() {
            client_saw |= matches!(e, ClientEvent::Connected { .. });
        }
        conn.is_some() && client_saw
    }));
    conn.unwrap()
}

#[test]
fn handshake_and_messages_both_ways() {
    let (mut server, mut client) = pair();
    let conn = connect(&mut server, &mut client);
    assert!(client.is_connected());
    assert_eq!(
        server.conn_addr(conn).map(|a| a.ip().is_loopback()),
        Some(true)
    );

    // client to server: ordered reliable messages and one unreliable
    for i in 0..10u8 {
        client.send(RELIABLE, &[b'c', i]).unwrap();
    }
    client.send(LOOSE, b"loose").unwrap();
    client.flush().unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; RECV_BUF];
    assert!(run(&mut server, &mut client, |s, _| {
        while let Some(r) = s.poll_recv(&mut buf) {
            assert_eq!(r.conn, conn);
            got.push((r.ch, buf[..r.len].to_vec()));
        }
        got.len() == 11
    }));
    let reliable: Vec<_> = got.iter().filter(|m| m.0 == RELIABLE).map(|m| m.1.clone()).collect();
    assert_eq!(reliable, (0..10u8).map(|i| vec![b'c', i]).collect::<Vec<_>>());
    assert!(got.contains(&(LOOSE, b"loose".to_vec())));

    // server to client
    for i in 0..10u8 {
        server.send(conn, RELIABLE, &[b's', i]).unwrap();
    }
    server.flush(conn).unwrap();
    server.service().unwrap();
    let mut got = Vec::new();
    assert!(run(&mut server, &mut client, |_, c| {
        while let Some((ch, n)) = c.poll_recv(&mut buf) {
            got.push((ch, buf[..n].to_vec()));
        }
        got.len() == 10
    }));
    assert_eq!(got, (0..10u8).map(|i| (RELIABLE, vec![b's', i])).collect::<Vec<_>>());

    let rtt = client.conn_stats().unwrap().rtt_us;
    assert!(rtt > 0 && rtt < 500_000, "rtt on loopback: {rtt} us");
}

#[test]
fn nothing_leaves_without_flush_until_a_timer() {
    let (mut server, mut client) = pair();
    let conn = connect(&mut server, &mut client);
    let before = server.conn_stats(conn).unwrap().packets_sent;
    server.send(conn, RELIABLE, b"queued").unwrap();
    server.service().unwrap();
    assert_eq!(server.conn_stats(conn).unwrap().packets_sent, before);
    server.flush(conn).unwrap();
    server.service().unwrap();
    assert_eq!(server.conn_stats(conn).unwrap().packets_sent, before + 1);
}

#[test]
fn send_now_reaches_the_server_without_a_client_pump() {
    let (mut server, mut client) = pair();
    connect(&mut server, &mut client);
    client.send_now(RELIABLE, b"click").unwrap().unwrap();
    let mut buf = [0u8; RECV_BUF];
    let end = Instant::now() + Duration::from_secs(2);
    let mut got = None;
    while got.is_none() && Instant::now() < end {
        // only the server runs: the datagram must already be on the wire
        server.pump(Some(Duration::from_millis(5))).unwrap();
        got = server.poll_recv(&mut buf).map(|r| buf[..r.len].to_vec());
    }
    assert_eq!(got.as_deref(), Some(&b"click"[..]));
}

#[test]
fn a_host_thread_can_read_the_socket_and_feed() {
    let (mut server, mut client) = pair();
    let conn = connect(&mut server, &mut client);
    let socket = client.try_clone_socket().unwrap();
    socket.set_nonblocking(false).unwrap();
    socket.set_read_timeout(Some(Duration::from_millis(500))).unwrap();

    server.send(conn, RELIABLE, b"to the thread").unwrap();
    server.flush(conn).unwrap();
    server.service().unwrap();

    let mut dgram = [0u8; 2048];
    let (n, from) = socket.recv_from(&mut dgram).unwrap();
    client.feed(from, &dgram[..n]).unwrap();
    let mut buf = [0u8; RECV_BUF];
    let (ch, len) = client.poll_recv(&mut buf).unwrap();
    assert_eq!((ch, &buf[..len]), (RELIABLE, &b"to the thread"[..]));

    // a fresh datagram is ignored when it claims to come from a stranger, and accepted from
    // the server (the same bytes: the first call must not have consumed them)
    server.send(conn, RELIABLE, b"second").unwrap();
    server.flush(conn).unwrap();
    server.service().unwrap();
    let (n, from) = socket.recv_from(&mut dgram).unwrap();
    let stranger: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    client.feed(stranger, &dgram[..n]).unwrap();
    assert!(client.poll_recv(&mut buf).is_none());
    client.feed(from, &dgram[..n]).unwrap();
    let (_, len) = client.poll_recv(&mut buf).unwrap();
    assert_eq!(&buf[..len], b"second");
}

#[test]
fn disconnect_is_seen_by_the_other_side() {
    let (mut server, mut client) = pair();
    let conn = connect(&mut server, &mut client);
    client.disconnect(7).unwrap();
    let mut reason = None;
    assert!(run(&mut server, &mut client, |s, _| {
        while let Some(e) = s.poll_event() {
            if let Event::Disconnected { conn: id, reason: r } = e {
                assert_eq!(id, conn);
                reason = Some(r);
            }
        }
        reason.is_some()
    }));
    assert_eq!(reason, Some(Closed::Remote(7)));

    let (mut server, mut client) = pair();
    let conn = connect(&mut server, &mut client);
    assert!(server.disconnect(conn, 9));
    let mut reason = None;
    assert!(run(&mut server, &mut client, |_, c| {
        while let Some(e) = c.poll_event() {
            if let ClientEvent::Disconnected(r) = e {
                reason = Some(r);
            }
        }
        reason.is_some()
    }));
    assert_eq!(reason, Some(Closed::Remote(9)));
}

#[test]
fn a_dead_server_port_does_not_break_the_client() {
    // On Windows a datagram to a closed port makes the next receive fail with
    // ConnectionReset; the driver must treat that as "nothing arrived".
    let port = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };
    let mut cfg = ClientConfig::new(PROTOCOL, channels());
    cfg.retry_interval_us = 20_000;
    cfg.handshake_timeout_us = 200_000;
    let mut client = UdpClient::connect(("127.0.0.1", port), cfg).unwrap();
    let end = Instant::now() + Duration::from_secs(2);
    let mut failed = false;
    while !failed && Instant::now() < end {
        client.pump(Some(Duration::from_millis(5))).unwrap();
        while let Some(e) = client.poll_event() {
            failed |= matches!(e, ClientEvent::Failed(_));
        }
    }
    assert!(failed, "the attempt must end with a timeout, not with an I/O error");
}

#[test]
fn both_ends_start_on_a_small_stack() {
    // A desktop shell calls `connect` from a UI thread with 1 MB of stack and many frames
    // already on it; the state (about 100 KB per connection) must never travel by value.
    let run = std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(|| {
            let (mut server, mut client) = pair();
            connect(&mut server, &mut client);
            client.is_connected()
        })
        .unwrap();
    assert!(run.join().unwrap());
}
