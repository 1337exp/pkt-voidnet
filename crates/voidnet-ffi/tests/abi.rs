//! The C ABI exercised the way a host would: raw blocks of memory, plain structs, integer codes.
//! Run with `--features small` to keep it light (and to run under Miri).
//! C ABI так, как его использует хозяин: сырые блоки памяти, простые структуры, целые коды.

use std::alloc::{alloc, dealloc, Layout};
use voidnet_ffi::*;

const PID: u64 = 0x5445_4501;

/// A block of host memory with the size and alignment the library asked for, filled with garbage
/// so that initialisation cannot rely on zero memory.
struct Block {
    ptr: *mut u8,
    layout: Layout,
}

impl Block {
    fn new(size: usize, align: usize, fill: u8) -> Self {
        let layout = Layout::from_size_align(size, align).unwrap();
        let ptr = unsafe { alloc(layout) };
        assert!(!ptr.is_null());
        unsafe { std::ptr::write_bytes(ptr, fill, size) };
        Self { ptr, layout }
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        unsafe { dealloc(self.ptr, self.layout) };
    }
}

fn addr(ip: [u8; 4], port: u16) -> VnAddr {
    let mut b = [0u8; 20];
    b[10] = 0xFF;
    b[11] = 0xFF;
    b[12..16].copy_from_slice(&ip);
    b[16..18].copy_from_slice(&port.to_be_bytes());
    VnAddr {
        len: 18,
        source_len: 16,
        bytes: b,
    }
}

fn server_cfg() -> VnServerConfig {
    let mut c: VnServerConfig = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { vn_server_config_default(&mut c, PID) }, VN_OK);
    c.channel_count = 3;
    c.channel_modes[..3].copy_from_slice(&[2, 0, 1]);
    c.max_per_source = u32::MAX;
    c.max_pending_per_source = u32::MAX;
    c.hello_burst = 50;
    c.blob_len = 7;
    c.blob[..7].copy_from_slice(b"tick=50");
    c
}

fn client_cfg() -> VnClientConfig {
    let mut c: VnClientConfig = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { vn_client_config_default(&mut c, PID) }, VN_OK);
    c.channel_count = 3;
    c.channel_modes[..3].copy_from_slice(&[2, 0, 1]);
    c
}

const SEED: [u8; 32] = [7; 32];
const NOW: u64 = 1_000_000_000;

fn new_server() -> (Block, *mut u8) {
    let b = Block::new(vn_server_size(), vn_server_align(), 0xA5);
    let cfg = server_cfg();
    let r = unsafe { vn_server_init(b.ptr, vn_server_size(), &cfg, SEED.as_ptr(), NOW) };
    assert_eq!(r, VN_OK);
    let p = b.ptr;
    (b, p)
}

fn new_client() -> (Block, *mut u8) {
    let b = Block::new(vn_client_size(), vn_client_align(), 0x5A);
    let cfg = client_cfg();
    let r = unsafe { vn_client_init(b.ptr, vn_client_size(), &cfg) };
    assert_eq!(r, VN_OK);
    let p = b.ptr;
    (b, p)
}

#[test]
fn abi_info_describes_the_build() {
    let mut i: VnAbiInfo = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { vn_abi_info(&mut i) }, VN_OK);
    assert_eq!(i.abi_version, vn_abi_version());
    assert_eq!(i.wire_version, 1);
    assert_eq!(i.sizeof_addr, 22);
    assert_eq!(i.sizeof_conn, 8);
    assert_eq!(i.sizeof_event, 36);
    assert_eq!(i.sizeof_recv, 16);
    assert_eq!(i.sizeof_client_event, 44);
    assert_eq!(i.sizeof_conn_stats, 112);
    assert_eq!(i.sizeof_server_stats, 136);
    assert_eq!(i.msg_max, 1200);
    assert_eq!(i.max_datagram, 1400);
    assert_eq!(i.max_channels, 16);
    assert_eq!(unsafe { vn_abi_info(std::ptr::null_mut()) }, VN_ERR_INVALID);
}

#[test]
fn init_rejects_bad_blocks_and_bad_configs() {
    let cfg = server_cfg();
    let size = vn_server_size();
    let align = vn_server_align();
    let b = Block::new(size + align, align, 0);
    unsafe {
        assert_eq!(
            vn_server_init(std::ptr::null_mut(), size, &cfg, SEED.as_ptr(), NOW),
            VN_ERR_INVALID
        );
        assert_eq!(
            vn_server_init(b.ptr, size, std::ptr::null(), SEED.as_ptr(), NOW),
            VN_ERR_INVALID
        );
        assert_eq!(
            vn_server_init(b.ptr, size, &cfg, std::ptr::null(), NOW),
            VN_ERR_INVALID
        );
        if align > 1 {
            assert_eq!(
                vn_server_init(b.ptr.add(1), size, &cfg, SEED.as_ptr(), NOW),
                VN_ERR_ALIGN
            );
        }
        assert_eq!(
            vn_server_init(b.ptr, size - 1, &cfg, SEED.as_ptr(), NOW),
            VN_ERR_NO_MEM
        );

        let mut bad = cfg;
        bad.channel_modes[1] = 9; // not a mode
        assert_eq!(
            vn_server_init(b.ptr, size, &bad, SEED.as_ptr(), NOW),
            VN_ERR_CONFIG
        );
        let mut bad = cfg;
        bad.channel_count = 17;
        assert_eq!(
            vn_server_init(b.ptr, size, &bad, SEED.as_ptr(), NOW),
            VN_ERR_CONFIG
        );
        let mut bad = cfg;
        bad.channel_modes[..4].copy_from_slice(&[2, 2, 2, 0]); // three reliable channels: not in this build
        bad.channel_count = 4;
        assert_eq!(
            vn_server_init(b.ptr, size, &bad, SEED.as_ptr(), NOW),
            VN_ERR_CONFIG
        );
        let mut bad = cfg;
        bad.blob_len = 33;
        assert_eq!(
            vn_server_init(b.ptr, size, &bad, SEED.as_ptr(), NOW),
            VN_ERR_CONFIG
        );
        let mut bad = cfg;
        bad.struct_size = 2;
        assert_eq!(
            vn_server_init(b.ptr, size, &bad, SEED.as_ptr(), NOW),
            VN_ERR_VERSION
        );
        assert_eq!(vn_server_init(b.ptr, size, &cfg, SEED.as_ptr(), NOW), VN_OK);
    }
}

#[test]
fn an_older_config_struct_gets_defaults_for_the_fields_it_does_not_have() {
    // a host built against an older header: only the first 8 bytes are real (struct_size and
    // app_version); everything after them must come from the defaults, so the server is useless
    // (no channels) but valid, and the call must not read past the host's struct
    let mut c = server_cfg();
    c.struct_size = 8;
    let b = Block::new(vn_server_size(), vn_server_align(), 0);
    // a config with no channels is valid: the library only needs the table to exist
    assert_eq!(
        unsafe { vn_server_init(b.ptr, vn_server_size(), &c, SEED.as_ptr(), NOW) },
        VN_OK
    );
}

#[test]
fn null_pointers_are_refused_not_followed() {
    unsafe {
        let n = std::ptr::null_mut::<u8>();
        let mut a = addr([1, 2, 3, 4], 5);
        let mut buf = [0u8; 1500];
        let mut ev: VnEvent = std::mem::zeroed();
        let mut rx: VnRecv = std::mem::zeroed();
        let conn = VnConn {
            index: 0,
            generation: 1,
        };
        // none of these may crash; calls that return a code return an error
        vn_server_handle_datagram(n as *mut _, &a, buf.as_ptr(), 10, NOW);
        vn_server_handle_timeout(n as *mut _, NOW);
        assert_eq!(vn_server_next_deadline(n as *const _), u64::MAX);
        assert_eq!(
            vn_server_poll_transmit(n as *mut _, buf.as_mut_ptr(), 1500, &mut a, NOW),
            0
        );
        assert_eq!(vn_server_poll_event(n as *mut _, &mut ev), VN_ERR_INVALID);
        assert_eq!(
            vn_server_send(n as *mut _, conn, 0, buf.as_ptr(), 3),
            VN_ERR_INVALID
        );
        assert_eq!(
            vn_server_poll_recv(n as *mut _, buf.as_mut_ptr(), 1500, &mut rx),
            VN_ERR_INVALID
        );
        assert_eq!(vn_server_flush(n as *mut _, conn), VN_ERR_INVALID);
        assert_eq!(vn_client_flush(n as *mut _), VN_ERR_INVALID);
        assert_eq!(vn_server_disconnect(n as *mut _, conn, 0), VN_ERR_INVALID);
        assert_eq!(vn_client_connect(n as *mut _, &a, 1, NOW), VN_ERR_INVALID);
        assert_eq!(vn_client_is_connected(n as *const _), 0);

        // and with a real server, bad arguments to otherwise valid calls
        let (_b, s) = new_server();
        let s = s as *mut _;
        assert_eq!(
            vn_server_poll_transmit(s, buf.as_mut_ptr(), 100, &mut a, NOW),
            0,
            "buffer under 1400"
        );
        assert_eq!(
            vn_server_poll_recv(s, buf.as_mut_ptr(), 100, &mut rx),
            VN_ERR_INVALID,
            "buffer under msg_max"
        );
        assert_eq!(
            vn_server_send(s, conn, 0, buf.as_ptr(), 5000),
            VN_ERR_TOO_BIG
        );
        assert_eq!(vn_server_send(s, conn, 0, n, 3), VN_ERR_INVALID);
        assert_eq!(
            vn_server_send(s, conn, 0, buf.as_ptr(), 3),
            VN_ERR_NOT_CONNECTED,
            "no such connection"
        );
        assert_eq!(
            vn_server_flush(s, conn),
            VN_ERR_NOT_CONNECTED,
            "no such connection"
        );
        // garbage datagrams and addresses are dropped
        vn_server_handle_datagram(s, &a, std::ptr::null(), 10, NOW);
        vn_server_handle_datagram(s, &a, buf.as_ptr(), 70_000, NOW);
        let bad_addr = VnAddr {
            len: 200,
            source_len: 1,
            bytes: [0; 20],
        };
        vn_server_handle_datagram(s, &bad_addr, buf.as_ptr(), 10, NOW);
        vn_server_handle_datagram(s, &a, buf.as_ptr(), 10, NOW);
        let mut st: VnServerStats = std::mem::zeroed();
        assert_eq!(vn_server_stats(s, &mut st), VN_OK);
        assert_eq!(st.accepted, 0);
    }
}

/// A host loop in miniature: two blocks, datagrams passed by hand, nothing but the C functions.
struct Net {
    now: u64,
    srv: *mut u8,
    cli: *mut u8,
    sa: VnAddr,
    ca: VnAddr,
    to_server: Vec<Vec<u8>>,
    to_client: Vec<Vec<u8>>,
    /// every datagram that crossed, for comparing runs
    log: Vec<Vec<u8>>,
    drop_every: u64,
    counter: u64,
}

impl Net {
    fn step(&mut self) {
        self.now += 1_000;
        let srv = self.srv as *mut _;
        let cli = self.cli as *mut _;
        unsafe {
            for d in std::mem::take(&mut self.to_server) {
                vn_server_handle_datagram(srv, &self.ca, d.as_ptr(), d.len(), self.now);
            }
            for d in std::mem::take(&mut self.to_client) {
                vn_client_handle_datagram(cli, &self.sa, d.as_ptr(), d.len(), self.now);
            }
            vn_server_handle_timeout(srv, self.now);
            let mut buf = [0u8; 1500];
            let mut to: VnAddr = std::mem::zeroed();
            loop {
                let n =
                    vn_server_poll_transmit(srv, buf.as_mut_ptr(), buf.len(), &mut to, self.now);
                if n == 0 {
                    break;
                }
                assert_eq!(to.len, 18);
                self.counter += 1;
                self.log.push(buf[..n].to_vec());
                if self.drop_every == 0 || !self.counter.is_multiple_of(self.drop_every) {
                    self.to_client.push(buf[..n].to_vec());
                }
            }
            loop {
                let n =
                    vn_client_poll_transmit(cli, buf.as_mut_ptr(), buf.len(), &mut to, self.now);
                if n == 0 {
                    break;
                }
                self.counter += 1;
                self.log.push(buf[..n].to_vec());
                if self.drop_every == 0 || !self.counter.is_multiple_of(self.drop_every) {
                    self.to_server.push(buf[..n].to_vec());
                }
            }
        }
    }

    fn run_for(&mut self, us: u64) {
        let end = self.now + us;
        while self.now < end {
            self.step();
        }
    }
}

fn net(drop_every: u64) -> (Block, Block, Net) {
    let (sb, s) = new_server();
    let (cb, c) = new_client();
    let n = Net {
        now: NOW,
        srv: s,
        cli: c,
        sa: addr([10, 255, 255, 1], 7000),
        ca: addr([10, 0, 0, 1], 5000),
        to_server: Vec::new(),
        to_client: Vec::new(),
        log: Vec::new(),
        drop_every,
        counter: 0,
    };
    (sb, cb, n)
}

#[test]
fn a_whole_conversation_through_the_c_functions() {
    let (_sb, _cb, mut n) = net(0);
    let (srv, cli) = (n.srv as *mut _, n.cli as *mut _);
    unsafe {
        assert_eq!(
            vn_client_connect(cli, &n.sa, 0x1122_3344_5566_7788, n.now),
            VN_OK
        );
        assert_eq!(
            vn_client_connect(cli, &n.sa, 1, n.now),
            VN_ERR_INVALID,
            "already connecting"
        );
    }
    n.run_for(300_000);
    unsafe {
        assert_eq!(vn_client_is_connected(cli), 1);
        // events on both sides
        let mut ce: VnClientEvent = std::mem::zeroed();
        assert_eq!(vn_client_poll_event(cli, &mut ce), 1);
        assert_eq!(ce.kind, VN_EVENT_CONNECTED);
        assert_eq!(&ce.blob[..ce.blob_len as usize], b"tick=50");
        assert_eq!(vn_client_poll_event(cli, &mut ce), 0);
        let mut se: VnEvent = std::mem::zeroed();
        assert_eq!(vn_server_poll_event(srv, &mut se), 1);
        assert_eq!(se.kind, VN_EVENT_CONNECTED);
        assert_eq!(&se.addr.bytes[..se.addr.len as usize], &n.ca.bytes[..18]);
        assert_eq!(se.addr.source_len, 16);
        let conn = se.conn;
        let mut got: VnAddr = std::mem::zeroed();
        assert_eq!(vn_server_conn_addr(srv, conn, &mut got), VN_OK);
        assert_eq!(vn_server_slots_in_use(srv), 1);

        // messages in all three modes, both ways
        for ch in 0..3u8 {
            let m = [ch; 5];
            assert_eq!(vn_server_send(srv, conn, ch, m.as_ptr(), m.len()), VN_OK);
            assert_eq!(vn_client_send(cli, ch, m.as_ptr(), m.len()), VN_OK);
        }
        assert_eq!(vn_server_flush(srv, conn), VN_OK);
        assert_eq!(vn_client_flush(cli), VN_OK);
        assert_eq!(
            vn_server_send(srv, conn, 3, [0u8].as_ptr(), 1),
            VN_ERR_NO_CHANNEL
        );
        assert_eq!(
            vn_server_send(srv, conn, 0, [0u8; 1300].as_ptr(), 1300),
            VN_ERR_TOO_BIG
        );
        n.run_for(200_000);

        let mut buf = [0u8; 1200];
        let (mut at_server, mut at_client) = (Vec::new(), Vec::new());
        let mut rx: VnRecv = std::mem::zeroed();
        while vn_server_poll_recv(srv, buf.as_mut_ptr(), buf.len(), &mut rx) == 1 {
            assert_eq!(rx.conn.index, conn.index);
            assert_eq!(rx.conn.generation, conn.generation);
            at_server.push((rx.ch, buf[..rx.len as usize].to_vec()));
        }
        let (mut ch, mut len) = (0u8, 0u32);
        while vn_client_poll_recv(cli, buf.as_mut_ptr(), buf.len(), &mut ch, &mut len) == 1 {
            at_client.push((ch, buf[..len as usize].to_vec()));
        }
        at_server.sort();
        at_client.sort();
        let want: Vec<(u8, Vec<u8>)> = (0..3u8).map(|c| (c, vec![c; 5])).collect();
        assert_eq!(at_server, want);
        assert_eq!(at_client, want);

        // statistics
        let mut cs: VnConnStats = std::mem::zeroed();
        assert_eq!(vn_server_conn_stats(srv, conn, &mut cs), VN_OK);
        assert!(cs.packets_sent > 0 && cs.packets_recv > 0);
        let mut ss: VnServerStats = std::mem::zeroed();
        assert_eq!(vn_server_stats(srv, &mut ss), VN_OK);
        assert_eq!((ss.accepted, ss.confirmed), (1, 1));
        assert_eq!(vn_client_conn_stats(cli, &mut cs), VN_OK);

        // the client leaves with a reason
        vn_client_disconnect(cli, 7);
        n.run_for(100_000);
        assert_eq!(vn_server_poll_event(srv, &mut se), 1);
        assert_eq!(
            (se.kind, se.reason_kind, se.reason_code),
            (VN_EVENT_DISCONNECTED, VN_REASON_REMOTE, 7)
        );
        assert_eq!(vn_server_slots_in_use(srv), 0);
        assert_eq!(
            vn_server_send(srv, conn, 0, [1u8].as_ptr(), 1),
            VN_ERR_NOT_CONNECTED,
            "stale handle"
        );
        assert_eq!(
            vn_server_flush(srv, conn),
            VN_ERR_NOT_CONNECTED,
            "stale handle"
        );
    }
}

#[test]
#[cfg_attr(miri, ignore)] // too many simulated steps for an interpreter
fn a_lossy_conversation_still_delivers_everything_reliable() {
    // every third datagram is lost
    let (_sb, _cb, mut n) = net(3);
    let (srv, cli) = (n.srv as *mut _, n.cli as *mut _);
    unsafe {
        vn_client_connect(cli, &n.sa, 42, n.now);
        n.run_for(3_000_000);
        assert_eq!(vn_client_is_connected(cli), 1);
        let mut se: VnEvent = std::mem::zeroed();
        assert_eq!(vn_server_poll_event(srv, &mut se), 1);
        let conn = se.conn;
        let mut sent = 0u8;
        let mut got = Vec::new();
        let mut buf = [0u8; 1200];
        let (mut ch, mut len) = (0u8, 0u32);
        for _ in 0..200 {
            if sent < 60 && vn_server_send(srv, conn, 0, [sent].as_ptr(), 1) == VN_OK {
                sent += 1;
            }
            assert_eq!(vn_server_flush(srv, conn), VN_OK);
            n.run_for(50_000);
            while vn_client_poll_recv(cli, buf.as_mut_ptr(), buf.len(), &mut ch, &mut len) == 1 {
                got.push(buf[0]);
            }
        }
        assert_eq!(got, (0..60u8).collect::<Vec<_>>());
    }
}

#[test]
#[cfg_attr(miri, ignore)] // builds the 6 MB native server by value
fn memory_given_by_the_host_gives_the_same_bytes_as_the_native_constructor() {
    // the same scripted run twice: once through zeroed, in-place initialised host memory, once with
    // `Server::new` and `Client::new` built as ordinary values; every datagram must be identical
    let (_sb, _cb, mut n) = net(0);
    unsafe {
        vn_client_connect(n.cli as *mut _, &n.sa, 0xABCD, n.now);
    }
    n.run_for(400_000);
    let via_abi = n.log.clone();

    use voidnet_core::wire::ChannelMode::*;
    let ch = voidnet_core::ChannelTable::new(&[ReliableOrdered, Unreliable, UnreliableSequenced])
        .unwrap();
    let mut sc = voidnet_core::ServerConfig::new(PID, ch);
    sc.max_per_source = usize::MAX;
    sc.max_pending_per_source = usize::MAX;
    sc.hello_burst = 50;
    sc.accept_blob = voidnet_core::Blob::new(b"tick=50").unwrap();
    let mut srv = Box::new(voidnet_core::Server::<64, 256, 160>::new(sc, SEED, NOW).unwrap());
    let mut cli =
        Box::new(voidnet_core::Client::new(voidnet_core::ClientConfig::new(PID, ch)).unwrap());
    let sa = voidnet_core::Addr::from_ipv4([10, 255, 255, 1], 7000);
    let ca = voidnet_core::Addr::from_ipv4([10, 0, 0, 1], 5000);
    cli.connect(sa, 0xABCD, NOW);
    let mut native = Vec::new();
    let (mut to_s, mut to_c): (Vec<Vec<u8>>, Vec<Vec<u8>>) = (Vec::new(), Vec::new());
    let mut now = NOW;
    while now < NOW + 400_000 {
        now += 1_000;
        for d in std::mem::take(&mut to_s) {
            srv.handle_datagram(&ca, &d, now);
        }
        for d in std::mem::take(&mut to_c) {
            cli.handle_datagram(&sa, &d, now);
        }
        srv.handle_timeout(now);
        let mut buf = [0u8; 1500];
        while let Some((_, len)) = srv.poll_transmit(&mut buf, now) {
            native.push(buf[..len].to_vec());
            to_c.push(buf[..len].to_vec());
        }
        while let Some((_, len)) = cli.poll_transmit(&mut buf, now) {
            native.push(buf[..len].to_vec());
            to_s.push(buf[..len].to_vec());
        }
    }
    assert!(
        via_abi.len() >= 6,
        "a handshake and a confirmation: {} datagrams",
        via_abi.len()
    );
    assert_eq!(
        via_abi, native,
        "in-place initialised state must behave exactly like the built one"
    );
}
