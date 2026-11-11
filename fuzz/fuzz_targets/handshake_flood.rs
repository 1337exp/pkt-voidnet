//! A structure-aware flood of the server: raw bytes, valid HELLOs, RESPONSEs built from the
//! cookies the server really issued (optionally corrupted), DATA with the tokens it really
//! handed out (optionally wrong), time jumps, secret rotation, host disconnects.
//!
//! Invariants after every operation: I1 (a reply is never longer than the datagram that
//! caused it, and one datagram causes at most one reply), I3 (slots and queues stay inside
//! their bounds), I4 (no panic), and no event is ever lost.
//!
//! Поток операций на сервер, знающий структуру: сырые байты, верные HELLO, RESPONSE по
//! настоящим кукам (иногда испорченным), DATA с настоящими токенами (иногда неверными),
//! скачки времени, ротация секрета, разрывы со стороны хозяина.
#![no_main]

use libfuzzer_sys::fuzz_target;
use voidnet_core::wire::{self, ChannelMode, Datagram, HelloFields, MAX_DATAGRAM};
use voidnet_core::{Addr, ChannelTable, ConnId, Event, Server, ServerConfig};

const PID: u64 = 0x5445_4501;
const POOL: usize = 12;

struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn u8(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }
    fn u64(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for i in 0..8 {
            v |= u64::from(self.u8()?) << (8 * i);
        }
        Some(v)
    }
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
}

#[derive(Clone, Copy, Default)]
struct Known {
    cookie: Option<(u32, u64, HelloFields)>,
    token: Option<u64>,
}

fuzz_target!(|data: &[u8]| {
    let channels = ChannelTable::new(&[
        ChannelMode::ReliableOrdered,
        ChannelMode::Unreliable,
        ChannelMode::UnreliableSequenced,
    ])
    .unwrap();
    let mut cfg = ServerConfig::new(PID, channels);
    cfg.max_connections = 6;
    cfg.max_per_source = 3;
    let mut srv: Server<8, 16, 32> = Server::new(cfg, [7; 32], 1_000_000_000);
    let table = channels;

    // twelve addresses: four IPs with three ports each
    let pool: Vec<Addr> = (0..POOL as u16)
        .map(|i| Addr::from_ipv4([10, 1, (i / 3) as u8, 1], 4000 + i))
        .collect();
    let mut known = [Known::default(); POOL];
    let mut now = 1_000_000_000u64;
    let mut conns: Vec<ConnId> = Vec::new();
    let mut r = Bytes(data);
    let mut buf = [0u8; MAX_DATAGRAM];

    while let (Some(op), Some(who)) = (r.u8(), r.u8()) {
        let who = usize::from(who) % POOL;
        let addr = pool[who];
        let mut input: Vec<u8> = Vec::new();
        match op % 8 {
            0 => {
                // raw bytes
                let Some(len) = r.u8() else { break };
                let Some(b) = r.take(usize::from(len)) else { break };
                input = b.to_vec();
            }
            1 => {
                // a valid HELLO, sometimes with a wrong field
                let Some(rnd) = r.u64() else { break };
                let Some(flip) = r.u8() else { break };
                let h = HelloFields {
                    wire_version: 1 ^ u8::from(flip == 1),
                    protocol_id: PID ^ u64::from(flip == 2),
                    app_version: u32::from(flip == 3),
                    config_hash: cfg.config_hash() ^ u32::from(flip == 4),
                    client_random: rnd,
                    caps: 0,
                };
                input = wire_hello(&mut buf, &h);
            }
            2 => {
                // a RESPONSE from the cookie the server issued to this address
                let Some(flip) = r.u8() else { break };
                let Some((coarse, cookie, h)) = known[who].cookie else { continue };
                let cookie = if flip == 1 { cookie ^ 1 } else { cookie };
                let mut h = h;
                if flip == 2 {
                    h.client_random ^= 1;
                }
                let n = wire::write_response(&mut buf, coarse, cookie, &h).unwrap();
                input = buf[..n].to_vec();
            }
            3 => {
                // DATA with the token the server issued, or a wrong one
                let Some(pn) = r.u8() else { break };
                let Some(kind) = r.u8() else { break };
                let token = match known[who].token {
                    Some(t) if kind & 0x80 == 0 => t,
                    Some(t) => t ^ 1,
                    None => 0xABCD,
                };
                let ch = table;
                let mut w = wire::DataWriter::new(&mut buf, ch.as_slice(), token, u16::from(pn)).unwrap();
                match kind & 3 {
                    0 => w.ping().unwrap(),
                    1 => w.disconnect(kind >> 2).unwrap(),
                    2 => w.msg(1, None, b"x").unwrap(),
                    _ => w.msg(0, Some(1), b"yz").unwrap(),
                }
                let n = w.finish().unwrap();
                input = buf[..n].to_vec();
            }
            4 => {
                let Some(dt) = r.u8() else { break };
                now = now.saturating_add(u64::from(dt) * 100_000);
                srv.handle_timeout(now);
            }
            5 => {
                let Some(k) = r.u8() else { break };
                srv.rotate_secret([k; 16], now);
            }
            6 => {
                if let Some(c) = conns.pop() {
                    srv.disconnect(c, 1);
                }
            }
            _ => now = now.saturating_add(1_000),
        }

        if !input.is_empty() || op % 8 <= 3 {
            // replies queued by host actions (disconnect) are not caused by this datagram
            while srv.poll_transmit(&mut buf, now).is_some() {}
            let in_len = input.len();
            srv.handle_datagram(&addr, &input, now);
            let mut replies = 0;
            while let Some((to, n)) = srv.poll_transmit(&mut buf, now) {
                replies += 1;
                // learn cookies and tokens the way a real client would
                if let Some(i) = pool.iter().position(|a| *a == to) {
                    match wire::parse(&buf[..n], table.as_slice()) {
                        Ok(Datagram::Challenge { coarse, cookie }) => {
                            if let Ok(Datagram::Hello(h)) = wire::parse(&input, table.as_slice()) {
                                known[i].cookie = Some((coarse, cookie, h));
                            }
                        }
                        Ok(Datagram::Accept { token, .. }) => known[i].token = Some(token),
                        _ => {}
                    }
                }
                // I1
                assert!(n <= in_len, "reply {n} B to a {in_len} B datagram");
            }
            assert!(replies <= 1, "one datagram caused {replies} replies");
        }

        // drain events like a host; handles may go stale, that is fine
        while let Some(e) = srv.poll_event() {
            if let Event::Connected { conn, .. } = e {
                conns.push(conn);
            }
        }
        // I3 and "no event is lost"
        assert!(srv.slots_in_use() <= 6);
        assert!(srv.pending_replies() <= voidnet_core::server::REPLY_CAP);
        assert_eq!(srv.stats().events_lost, 0);
    }
});

fn wire_hello(buf: &mut [u8], h: &HelloFields) -> Vec<u8> {
    let n = wire::write_hello(buf, h).unwrap();
    buf[..n].to_vec()
}
