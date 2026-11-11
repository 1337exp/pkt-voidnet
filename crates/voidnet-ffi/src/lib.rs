//! The C ABI of pkt-voidnet. `unsafe` is allowed in this crate only.
//!
//! Rules of the boundary (see `docs/wire.md` and the specification):
//! - the host owns every byte of memory: it asks `vn_*_size` and `vn_*_align`, allocates, and
//!   gives the block to `vn_*_init`; the library never allocates and never frees;
//! - no pointer given to a call is kept after it returns; the only thing the host must keep alive
//!   is the block itself, and it must not move or share it between threads without locking;
//! - no callbacks, no threads, no clock, no randomness: time and entropy come in as arguments;
//! - every function returns a plain integer: 0 or a count on success, a negative `VN_ERR_*` code
//!   on failure, and nothing panics (the release library is built with `panic = "abort"`);
//! - structs the host fills start with `struct_size` and only ever grow at the end.
//!
//! C ABI pkt-voidnet. `unsafe` разрешён только в этом крейте. Память целиком принадлежит
//! хозяину; библиотека её не выделяет и не освобождает; ни один указатель не хранится после
//! возврата из вызова; нет колбэков, потоков, часов и случайности; функции возвращают числа, а
//! структуры, которые заполняет хозяин, начинаются с `struct_size` и растут только в конце.

// The release library is built with `--features abi`: `no_std`, `panic = "abort"`.
// Without the feature the crate is an ordinary std library, so `cargo test` works.
#![cfg_attr(feature = "abi", no_std)]
#![allow(clippy::missing_safety_doc)]

use core::mem::{align_of, size_of};
use core::ptr;
use core::slice;

use voidnet_core::conn::MSG_MAX;
use voidnet_core::wire::{ChannelMode, MAX_BLOB, MAX_CHANNELS, MAX_DATAGRAM};
use voidnet_core::{
    Addr, Blob, ChannelTable, Client, ClientConfig, ClientEvent, Closed, ConnId, Event, Failed,
    SendError, Server, ServerConfig,
};

// ------------------------------------------------------------------------------ profile

/// Connection slots, rate-limit entries and event slots of the library build.
/// Слоты соединений, записи лимитера и места под события этой сборки.
#[cfg(not(feature = "small"))]
type Srv = Server<64, 256, 160>;
#[cfg(feature = "small")]
type Srv = Server<4, 16, 16>;

#[cfg(not(feature = "small"))]
const SLOTS: u32 = 64;
#[cfg(feature = "small")]
const SLOTS: u32 = 4;

// ------------------------------------------------------------------------------ codes

pub const VN_OK: i32 = 0;
pub const VN_ERR_INVALID: i32 = -1;
pub const VN_ERR_FULL: i32 = -2;
pub const VN_ERR_TOO_BIG: i32 = -3;
pub const VN_ERR_NO_CHANNEL: i32 = -4;
pub const VN_ERR_NOT_CONNECTED: i32 = -5;
pub const VN_ERR_NO_MEM: i32 = -6;
pub const VN_ERR_ALIGN: i32 = -7;
pub const VN_ERR_CONFIG: i32 = -8;
pub const VN_ERR_VERSION: i32 = -9;

pub const VN_EVENT_CONNECTED: u32 = 1;
pub const VN_EVENT_DISCONNECTED: u32 = 2;
pub const VN_EVENT_FAILED: u32 = 3;

pub const VN_REASON_NONE: u8 = 0;
pub const VN_REASON_LOCAL: u8 = 1;
pub const VN_REASON_REMOTE: u8 = 2;
pub const VN_REASON_TIMEOUT: u8 = 3;
pub const VN_REASON_REPLACED: u8 = 4;
/// `reason_kind` of a failed connection attempt: the server answered REJECT with `reason_code`.
pub const VN_REASON_REJECTED: u8 = 5;
/// `reason_kind` of a failed connection attempt: no answer in time.
pub const VN_REASON_NO_ANSWER: u8 = 6;

fn send_code(e: SendError) -> i32 {
    match e {
        SendError::NoChannel => VN_ERR_NO_CHANNEL,
        SendError::TooBig => VN_ERR_TOO_BIG,
        SendError::Full => VN_ERR_FULL,
        SendError::NotConnected => VN_ERR_NOT_CONNECTED,
    }
}

// ------------------------------------------------------------------------------ plain types

/// A peer address: at most 20 bytes chosen by the host; the first `source_len` bytes name the
/// source for rate limits (the IP without the port).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VnAddr {
    pub len: u8,
    pub source_len: u8,
    pub bytes: [u8; 20],
}

/// Handle of a connection: slot and generation.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VnConn {
    pub index: u32,
    pub generation: u32,
}

/// Something the host should know about a server connection.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VnEvent {
    pub kind: u32,
    pub conn: VnConn,
    pub addr: VnAddr,
    pub reason_kind: u8,
    pub reason_code: u8,
}

/// A message received by the server.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VnRecv {
    pub conn: VnConn,
    pub ch: u8,
    pub _reserved: [u8; 3],
    pub len: u32,
}

/// Something the host should know about the client connection.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VnClientEvent {
    pub kind: u32,
    pub reason_kind: u8,
    pub reason_code: u8,
    pub blob_len: u8,
    pub _reserved: u8,
    pub caps: u32,
    pub blob: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VnConnStats {
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub ack_only_sent: u64,
    pub packets_lost: u64,
    pub messages_resent: u64,
    pub duplicates_dropped: u64,
    pub refused_capacity: u64,
    pub probes: u64,
    pub rtt_us: u64,
    pub rtt_var_us: u64,
    pub min_rtt_us: u64,
    pub latest_rtt_us: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VnServerStats {
    pub datagrams: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub parse_errors: u64,
    pub hello: u64,
    pub response: u64,
    pub rate_limited_source: u64,
    pub rate_limited_global: u64,
    pub bad_cookie: u64,
    pub stale_cookie: u64,
    pub challenges: u64,
    pub accepted: u64,
    pub rejected_full: u64,
    pub deferred_pending: u64,
    pub confirmed: u64,
    pub bad_token: u64,
    pub unknown_peer: u64,
}

/// Settings of a server. Fill it with `vn_server_config_default`, then change what you need.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VnServerConfig {
    pub struct_size: u32,
    pub app_version: u32,
    pub protocol_id: u64,
    pub rotation_interval_us: u64,
    pub unconfirmed_timeout_us: u64,
    pub idle_timeout_us: u64,
    pub max_ack_delay_us: u64,
    pub keepalive_us: u64,
    pub initial_rtt_us: u64,
    /// At most the slots of the build; 0 means all of them.
    pub max_connections: u32,
    /// All connections from one source; `0xFFFF_FFFF` means no limit.
    pub max_per_source: u32,
    /// Unconfirmed connections from one source.
    pub max_pending_per_source: u32,
    pub hello_rate_per_s: u32,
    pub hello_burst: u32,
    pub global_rate_per_s: u32,
    pub global_burst: u32,
    pub cookie_freshness_s: u32,
    pub max_datagram: u16,
    pub channel_count: u8,
    pub blob_len: u8,
    /// 0 unreliable, 1 unreliable_sequenced, 2 reliable_ordered.
    pub channel_modes: [u8; 16],
    pub blob: [u8; 32],
}

/// Settings of a client. Fill it with `vn_client_config_default`, then change what you need.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VnClientConfig {
    pub struct_size: u32,
    pub app_version: u32,
    pub protocol_id: u64,
    pub retry_interval_us: u64,
    pub handshake_timeout_us: u64,
    pub idle_timeout_us: u64,
    pub max_ack_delay_us: u64,
    pub keepalive_us: u64,
    pub initial_rtt_us: u64,
    pub max_datagram: u16,
    pub channel_count: u8,
    pub response_retries: u8,
    pub channel_modes: [u8; 16],
}

/// Sizes and limits of this build, so a binding can check its own struct definitions.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VnAbiInfo {
    pub abi_version: u32,
    pub wire_version: u32,
    pub sizeof_addr: u32,
    pub sizeof_conn: u32,
    pub sizeof_event: u32,
    pub sizeof_recv: u32,
    pub sizeof_client_event: u32,
    pub sizeof_conn_stats: u32,
    pub sizeof_server_stats: u32,
    pub sizeof_server_config: u32,
    pub sizeof_client_config: u32,
    pub msg_max: u32,
    pub max_datagram: u32,
    pub server_slots: u32,
    pub max_channels: u32,
}

// ------------------------------------------------------------------------------ helpers

fn modes(count: u8, raw: &[u8; 16]) -> Option<ChannelTable> {
    let n = usize::from(count);
    if n > MAX_CHANNELS {
        return None;
    }
    let mut v = [ChannelMode::Unreliable; MAX_CHANNELS];
    for (d, s) in v.iter_mut().zip(raw.iter()).take(n) {
        *d = match *s {
            0 => ChannelMode::Unreliable,
            1 => ChannelMode::UnreliableSequenced,
            2 => ChannelMode::ReliableOrdered,
            _ => return None,
        };
    }
    ChannelTable::new(v.get(..n)?)
}

unsafe fn addr_from(a: *const VnAddr) -> Option<Addr> {
    let a = unsafe { a.as_ref() }?;
    let bytes = a.bytes.get(..usize::from(a.len))?;
    Addr::new(bytes, usize::from(a.source_len))
}

fn addr_to(a: &Addr, out: &mut VnAddr) {
    let b = a.as_bytes();
    out.len = b.len() as u8;
    out.source_len = a.source().len() as u8;
    out.bytes = [0; 20];
    for (d, s) in out.bytes.iter_mut().zip(b) {
        *d = *s;
    }
}

fn conn_from(c: VnConn) -> ConnId {
    ConnId {
        index: c.index,
        generation: c.generation,
    }
}

fn conn_to(c: ConnId) -> VnConn {
    VnConn {
        index: c.index,
        generation: c.generation,
    }
}

fn reason(c: Closed) -> (u8, u8) {
    match c {
        Closed::Local(r) => (VN_REASON_LOCAL, r),
        Closed::Remote(r) => (VN_REASON_REMOTE, r),
        Closed::Timeout => (VN_REASON_TIMEOUT, 0),
        Closed::Replaced => (VN_REASON_REPLACED, 0),
    }
}

/// Copy the host's config struct (which may be older or newer than ours) over our defaults.
unsafe fn read_config<T: Copy>(host: *const T, default: T) -> Option<T> {
    let first = unsafe { ptr::read_unaligned(host as *const u32) };
    let mut ours = default;
    let n = (first as usize).min(size_of::<T>());
    if n < size_of::<u32>() {
        return None;
    }
    unsafe { ptr::copy_nonoverlapping(host as *const u8, &mut ours as *mut T as *mut u8, n) };
    Some(ours)
}

/// Zero the block, check it, and return it as the library type.
unsafe fn place<'a, T>(mem: *mut u8, len: usize) -> Result<&'a mut T, i32> {
    if mem.is_null() {
        return Err(VN_ERR_INVALID);
    }
    if !(mem as usize).is_multiple_of(align_of::<T>()) {
        return Err(VN_ERR_ALIGN);
    }
    if len < size_of::<T>() {
        return Err(VN_ERR_NO_MEM);
    }
    // Every type of the core is valid with all bytes zero (enums are `repr(u8)` with a zero first
    // variant, no `Option` or reference is stored): `reset` then writes the real state.
    unsafe {
        ptr::write_bytes(mem, 0, size_of::<T>());
        Ok(&mut *(mem as *mut T))
    }
}

// ------------------------------------------------------------------------------ general

/// `(major << 16) | minor` of the ABI. / Версия ABI.
#[no_mangle]
pub extern "C" fn vn_abi_version() -> u32 {
    voidnet_core::ABI_VERSION
}

/// Wire format generation (`wire_version` in HELLO). / Поколение формата на проводе.
#[no_mangle]
pub extern "C" fn vn_wire_version() -> u32 {
    u32::from(voidnet_core::wire::WIRE_VERSION)
}

/// Fill `out` with the sizes and limits of this build.
#[no_mangle]
pub unsafe extern "C" fn vn_abi_info(out: *mut VnAbiInfo) -> i32 {
    let Some(o) = (unsafe { out.as_mut() }) else {
        return VN_ERR_INVALID;
    };
    *o = VnAbiInfo {
        abi_version: vn_abi_version(),
        wire_version: vn_wire_version(),
        sizeof_addr: size_of::<VnAddr>() as u32,
        sizeof_conn: size_of::<VnConn>() as u32,
        sizeof_event: size_of::<VnEvent>() as u32,
        sizeof_recv: size_of::<VnRecv>() as u32,
        sizeof_client_event: size_of::<VnClientEvent>() as u32,
        sizeof_conn_stats: size_of::<VnConnStats>() as u32,
        sizeof_server_stats: size_of::<VnServerStats>() as u32,
        sizeof_server_config: size_of::<VnServerConfig>() as u32,
        sizeof_client_config: size_of::<VnClientConfig>() as u32,
        msg_max: MSG_MAX as u32,
        max_datagram: MAX_DATAGRAM as u32,
        server_slots: SLOTS,
        max_channels: MAX_CHANNELS as u32,
    };
    VN_OK
}

// ------------------------------------------------------------------------------ server

fn server_defaults() -> VnServerConfig {
    let d = ServerConfig::new(0, ChannelTable::default());
    VnServerConfig {
        struct_size: size_of::<VnServerConfig>() as u32,
        app_version: 0,
        protocol_id: 0,
        rotation_interval_us: d.rotation_interval_us,
        unconfirmed_timeout_us: d.unconfirmed_timeout_us,
        idle_timeout_us: d.idle_timeout_us,
        max_ack_delay_us: d.max_ack_delay_us,
        keepalive_us: d.keepalive_us,
        initial_rtt_us: d.initial_rtt_us,
        max_connections: 0,
        max_per_source: d.max_per_source as u32,
        max_pending_per_source: d.max_pending_per_source as u32,
        hello_rate_per_s: d.hello_rate_per_s,
        hello_burst: d.hello_burst,
        global_rate_per_s: d.global_rate_per_s,
        global_burst: d.global_burst,
        cookie_freshness_s: d.cookie_freshness_s,
        max_datagram: d.max_datagram,
        channel_count: 0,
        blob_len: 0,
        channel_modes: [0; 16],
        blob: [0; 32],
    }
}

/// Fill `cfg` with defaults and `protocol_id`; then set the channel table and whatever else.
#[no_mangle]
pub unsafe extern "C" fn vn_server_config_default(
    cfg: *mut VnServerConfig,
    protocol_id: u64,
) -> i32 {
    let Some(c) = (unsafe { cfg.as_mut() }) else {
        return VN_ERR_INVALID;
    };
    *c = server_defaults();
    c.protocol_id = protocol_id;
    VN_OK
}

fn server_config(c: &VnServerConfig) -> Option<ServerConfig> {
    let channels = modes(c.channel_count, &c.channel_modes)?;
    let mut s = ServerConfig::new(c.protocol_id, channels);
    s.app_version = c.app_version;
    s.max_datagram = c.max_datagram;
    s.max_connections = if c.max_connections == 0 {
        usize::MAX
    } else {
        c.max_connections as usize
    };
    s.max_per_source = if c.max_per_source == u32::MAX {
        usize::MAX
    } else {
        c.max_per_source as usize
    };
    s.max_pending_per_source = if c.max_pending_per_source == u32::MAX {
        usize::MAX
    } else {
        c.max_pending_per_source as usize
    };
    s.hello_rate_per_s = c.hello_rate_per_s;
    s.hello_burst = c.hello_burst;
    s.global_rate_per_s = c.global_rate_per_s;
    s.global_burst = c.global_burst;
    s.cookie_freshness_s = c.cookie_freshness_s;
    s.rotation_interval_us = c.rotation_interval_us;
    s.unconfirmed_timeout_us = c.unconfirmed_timeout_us;
    s.idle_timeout_us = c.idle_timeout_us;
    s.max_ack_delay_us = c.max_ack_delay_us;
    s.keepalive_us = c.keepalive_us;
    s.initial_rtt_us = c.initial_rtt_us;
    if usize::from(c.blob_len) > MAX_BLOB {
        return None;
    }
    s.accept_blob = Blob::new(c.blob.get(..usize::from(c.blob_len))?)?;
    Some(s)
}

/// Bytes the host must provide for a server. / Сколько байт дать серверу.
#[no_mangle]
pub extern "C" fn vn_server_size() -> usize {
    size_of::<Srv>()
}

/// Alignment of that block. / Выравнивание блока.
#[no_mangle]
pub extern "C" fn vn_server_align() -> usize {
    align_of::<Srv>()
}

/// Initialise a server in the host's block. `seed` is 32 fresh random bytes. Returns 0 or a
/// negative `VN_ERR_*`.
#[no_mangle]
pub unsafe extern "C" fn vn_server_init(
    mem: *mut u8,
    len: usize,
    cfg: *const VnServerConfig,
    seed: *const u8,
    now_us: u64,
) -> i32 {
    if cfg.is_null() || seed.is_null() {
        return VN_ERR_INVALID;
    }
    let Some(host) = (unsafe { read_config(cfg, server_defaults()) }) else {
        return VN_ERR_VERSION;
    };
    let Some(sc) = server_config(&host) else {
        return VN_ERR_CONFIG;
    };
    let mut s = [0u8; 32];
    unsafe { ptr::copy_nonoverlapping(seed, s.as_mut_ptr(), 32) };
    let srv: &mut Srv = match unsafe { place(mem, len) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    match srv.reset(sc, s, now_us) {
        Ok(()) => VN_OK,
        Err(_) => VN_ERR_CONFIG,
    }
}

/// Replace the cookie secret with 16 fresh random bytes (call it on a timer, see
/// `vn_server_next_deadline`).
#[no_mangle]
pub unsafe extern "C" fn vn_server_rotate_secret(srv: *mut Srv, fresh: *const u8, now_us: u64) {
    let (Some(s), false) = (unsafe { srv.as_mut() }, fresh.is_null()) else {
        return;
    };
    let mut k = [0u8; 16];
    unsafe { ptr::copy_nonoverlapping(fresh, k.as_mut_ptr(), 16) };
    s.rotate_secret(k, now_us);
}

/// Hand a received datagram to the server.
#[no_mangle]
pub unsafe extern "C" fn vn_server_handle_datagram(
    srv: *mut Srv,
    from: *const VnAddr,
    data: *const u8,
    len: usize,
    now_us: u64,
) {
    let (Some(s), Some(a)) = (unsafe { srv.as_mut() }, unsafe { addr_from(from) }) else {
        return;
    };
    if data.is_null() || len > 65_535 {
        return;
    }
    s.handle_datagram(&a, unsafe { slice::from_raw_parts(data, len) }, now_us);
}

/// Run the timers; call it when `vn_server_next_deadline` has passed, or every loop iteration.
#[no_mangle]
pub unsafe extern "C" fn vn_server_handle_timeout(srv: *mut Srv, now_us: u64) {
    if let Some(s) = unsafe { srv.as_mut() } {
        s.handle_timeout(now_us);
    }
}

/// When the host should call `vn_server_handle_timeout` next; `UINT64_MAX` if never.
#[no_mangle]
pub unsafe extern "C" fn vn_server_next_deadline(srv: *const Srv) -> u64 {
    unsafe { srv.as_ref() }
        .and_then(|s| s.next_deadline())
        .unwrap_or(u64::MAX)
}

/// The next datagram to send: its length, with the destination in `to`; 0 if there is none.
/// `cap` must be at least 1400.
#[no_mangle]
pub unsafe extern "C" fn vn_server_poll_transmit(
    srv: *mut Srv,
    buf: *mut u8,
    cap: usize,
    to: *mut VnAddr,
    now_us: u64,
) -> usize {
    let (Some(s), Some(t)) = (unsafe { srv.as_mut() }, unsafe { to.as_mut() }) else {
        return 0;
    };
    if buf.is_null() || cap < MAX_DATAGRAM {
        return 0;
    }
    let out = unsafe { slice::from_raw_parts_mut(buf, cap) };
    match s.poll_transmit(out, now_us) {
        Some((a, n)) => {
            addr_to(&a, t);
            n
        }
        None => 0,
    }
}

/// The next event: 1 and `out` filled, or 0.
#[no_mangle]
pub unsafe extern "C" fn vn_server_poll_event(srv: *mut Srv, out: *mut VnEvent) -> i32 {
    let (Some(s), Some(o)) = (unsafe { srv.as_mut() }, unsafe { out.as_mut() }) else {
        return VN_ERR_INVALID;
    };
    let Some(e) = s.poll_event() else {
        return 0;
    };
    match e {
        Event::Connected { conn, addr } => {
            o.kind = VN_EVENT_CONNECTED;
            o.conn = conn_to(conn);
            addr_to(&addr, &mut o.addr);
            o.reason_kind = VN_REASON_NONE;
            o.reason_code = 0;
        }
        Event::Disconnected { conn, reason: r } => {
            o.kind = VN_EVENT_DISCONNECTED;
            o.conn = conn_to(conn);
            o.addr = VnAddr {
                len: 0,
                source_len: 0,
                bytes: [0; 20],
            };
            (o.reason_kind, o.reason_code) = reason(r);
        }
    }
    1
}

/// Queue a message for a connection. 0, or `VN_ERR_FULL` (the reliable window is full, nothing was
/// queued), `VN_ERR_TOO_BIG`, `VN_ERR_NO_CHANNEL`, `VN_ERR_NOT_CONNECTED`.
#[no_mangle]
pub unsafe extern "C" fn vn_server_send(
    srv: *mut Srv,
    conn: VnConn,
    ch: u8,
    data: *const u8,
    len: usize,
) -> i32 {
    let Some(s) = (unsafe { srv.as_mut() }) else {
        return VN_ERR_INVALID;
    };
    if data.is_null() && len > 0 || len > MSG_MAX {
        return if len > MSG_MAX {
            VN_ERR_TOO_BIG
        } else {
            VN_ERR_INVALID
        };
    }
    let d: &[u8] = if len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(data, len) }
    };
    match s.send(conn_from(conn), ch, d) {
        Ok(()) => VN_OK,
        Err(e) => send_code(e),
    }
}

/// The next received message: 1 with `out` filled and the bytes in `buf`, or 0. `cap` must be at
/// least `msg_max` (see `vn_abi_info`).
#[no_mangle]
pub unsafe extern "C" fn vn_server_poll_recv(
    srv: *mut Srv,
    buf: *mut u8,
    cap: usize,
    out: *mut VnRecv,
) -> i32 {
    let (Some(s), Some(o)) = (unsafe { srv.as_mut() }, unsafe { out.as_mut() }) else {
        return VN_ERR_INVALID;
    };
    if buf.is_null() || cap < MSG_MAX {
        return VN_ERR_INVALID;
    }
    let b = unsafe { slice::from_raw_parts_mut(buf, cap) };
    match s.poll_recv(b) {
        Some(r) => {
            o.conn = conn_to(r.conn);
            o.ch = r.ch;
            o.len = r.len as u32;
            1
        }
        None => 0,
    }
}

/// Close a connection: DISCONNECT goes out three times, the slot is free at once.
#[no_mangle]
pub unsafe extern "C" fn vn_server_disconnect(srv: *mut Srv, conn: VnConn, reason: u8) -> i32 {
    let Some(s) = (unsafe { srv.as_mut() }) else {
        return VN_ERR_INVALID;
    };
    if s.disconnect(conn_from(conn), reason) {
        VN_OK
    } else {
        VN_ERR_NOT_CONNECTED
    }
}

fn fill_stats(s: &voidnet_core::ConnStats, o: &mut VnConnStats) {
    *o = VnConnStats {
        packets_sent: s.packets_sent,
        packets_recv: s.packets_recv,
        bytes_sent: s.bytes_sent,
        bytes_recv: s.bytes_recv,
        ack_only_sent: s.ack_only_sent,
        packets_lost: s.packets_lost,
        messages_resent: s.messages_resent,
        duplicates_dropped: s.duplicates_dropped,
        refused_capacity: s.refused_capacity,
        probes: s.probes,
        rtt_us: s.rtt_us,
        rtt_var_us: s.rtt_var_us,
        min_rtt_us: s.min_rtt_us,
        latest_rtt_us: s.latest_rtt_us,
    };
}

/// Counters, RTT and traffic of one connection.
#[no_mangle]
pub unsafe extern "C" fn vn_server_conn_stats(
    srv: *const Srv,
    conn: VnConn,
    out: *mut VnConnStats,
) -> i32 {
    let (Some(s), Some(o)) = (unsafe { srv.as_ref() }, unsafe { out.as_mut() }) else {
        return VN_ERR_INVALID;
    };
    match s.conn_stats(conn_from(conn)) {
        Some(st) => {
            fill_stats(&st, o);
            VN_OK
        }
        None => VN_ERR_NOT_CONNECTED,
    }
}

/// The address of a connection. / Адрес соединения.
#[no_mangle]
pub unsafe extern "C" fn vn_server_conn_addr(
    srv: *const Srv,
    conn: VnConn,
    out: *mut VnAddr,
) -> i32 {
    let (Some(s), Some(o)) = (unsafe { srv.as_ref() }, unsafe { out.as_mut() }) else {
        return VN_ERR_INVALID;
    };
    match s.conn_addr(conn_from(conn)) {
        Some(a) => {
            addr_to(&a, o);
            VN_OK
        }
        None => VN_ERR_NOT_CONNECTED,
    }
}

/// Server-wide counters. / Счётчики сервера.
#[no_mangle]
pub unsafe extern "C" fn vn_server_stats(srv: *const Srv, out: *mut VnServerStats) -> i32 {
    let (Some(s), Some(o)) = (unsafe { srv.as_ref() }, unsafe { out.as_mut() }) else {
        return VN_ERR_INVALID;
    };
    let t = s.stats();
    *o = VnServerStats {
        datagrams: t.datagrams,
        bytes_in: t.bytes_in,
        bytes_out: t.bytes_out,
        parse_errors: t.parse_errors,
        hello: t.hello,
        response: t.response,
        rate_limited_source: t.rate_limited_source,
        rate_limited_global: t.rate_limited_global,
        bad_cookie: t.bad_cookie,
        stale_cookie: t.stale_cookie,
        challenges: t.challenges,
        accepted: t.accepted,
        rejected_full: t.rejected_full,
        deferred_pending: t.deferred_pending,
        confirmed: t.confirmed,
        bad_token: t.bad_token,
        unknown_peer: t.unknown_peer,
    };
    VN_OK
}

/// How many slots are taken, confirmed or not. / Сколько слотов занято.
#[no_mangle]
pub unsafe extern "C" fn vn_server_slots_in_use(srv: *const Srv) -> u32 {
    unsafe { srv.as_ref() }.map_or(0, |s| s.slots_in_use() as u32)
}

// ------------------------------------------------------------------------------ client

fn client_defaults() -> VnClientConfig {
    VnClientConfig {
        struct_size: size_of::<VnClientConfig>() as u32,
        app_version: 0,
        protocol_id: 0,
        retry_interval_us: 500_000,
        handshake_timeout_us: 10_000_000,
        idle_timeout_us: 30_000_000,
        max_ack_delay_us: 25_000,
        keepalive_us: 1_000_000,
        initial_rtt_us: 100_000,
        max_datagram: MAX_DATAGRAM as u16,
        channel_count: 0,
        response_retries: 4,
        channel_modes: [0; 16],
    }
}

/// Fill `cfg` with defaults and `protocol_id`; then set the channel table and whatever else.
#[no_mangle]
pub unsafe extern "C" fn vn_client_config_default(
    cfg: *mut VnClientConfig,
    protocol_id: u64,
) -> i32 {
    let Some(c) = (unsafe { cfg.as_mut() }) else {
        return VN_ERR_INVALID;
    };
    *c = client_defaults();
    c.protocol_id = protocol_id;
    VN_OK
}

fn client_config(c: &VnClientConfig) -> Option<ClientConfig> {
    let mut s = ClientConfig::new(c.protocol_id, modes(c.channel_count, &c.channel_modes)?);
    s.app_version = c.app_version;
    s.max_datagram = c.max_datagram;
    s.retry_interval_us = c.retry_interval_us;
    s.response_retries = c.response_retries;
    s.handshake_timeout_us = c.handshake_timeout_us;
    s.idle_timeout_us = c.idle_timeout_us;
    s.max_ack_delay_us = c.max_ack_delay_us;
    s.keepalive_us = c.keepalive_us;
    s.initial_rtt_us = c.initial_rtt_us;
    Some(s)
}

#[no_mangle]
pub extern "C" fn vn_client_size() -> usize {
    size_of::<Client>()
}

#[no_mangle]
pub extern "C" fn vn_client_align() -> usize {
    align_of::<Client>()
}

/// Initialise a client in the host's block. Returns 0 or a negative `VN_ERR_*`.
#[no_mangle]
pub unsafe extern "C" fn vn_client_init(
    mem: *mut u8,
    len: usize,
    cfg: *const VnClientConfig,
) -> i32 {
    if cfg.is_null() {
        return VN_ERR_INVALID;
    }
    let Some(host) = (unsafe { read_config(cfg, client_defaults()) }) else {
        return VN_ERR_VERSION;
    };
    let Some(cc) = client_config(&host) else {
        return VN_ERR_CONFIG;
    };
    let c: &mut Client = match unsafe { place(mem, len) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    match c.reset(cc) {
        Ok(()) => VN_OK,
        Err(_) => VN_ERR_CONFIG,
    }
}

/// Begin a connection attempt. `random` is 8 fresh random bytes from the host.
#[no_mangle]
pub unsafe extern "C" fn vn_client_connect(
    c: *mut Client,
    server: *const VnAddr,
    random: u64,
    now_us: u64,
) -> i32 {
    let (Some(cl), Some(a)) = (unsafe { c.as_mut() }, unsafe { addr_from(server) }) else {
        return VN_ERR_INVALID;
    };
    if cl.connect(a, random, now_us) {
        VN_OK
    } else {
        VN_ERR_INVALID
    }
}

#[no_mangle]
pub unsafe extern "C" fn vn_client_handle_datagram(
    c: *mut Client,
    from: *const VnAddr,
    data: *const u8,
    len: usize,
    now_us: u64,
) {
    let (Some(cl), Some(a)) = (unsafe { c.as_mut() }, unsafe { addr_from(from) }) else {
        return;
    };
    if data.is_null() || len > 65_535 {
        return;
    }
    cl.handle_datagram(&a, unsafe { slice::from_raw_parts(data, len) }, now_us);
}

/// The next datagram to send: its length, destination in `to`; 0 if none. `cap` at least 1400.
/// Call it every loop iteration: it also runs the client's timers.
#[no_mangle]
pub unsafe extern "C" fn vn_client_poll_transmit(
    c: *mut Client,
    buf: *mut u8,
    cap: usize,
    to: *mut VnAddr,
    now_us: u64,
) -> usize {
    let (Some(cl), Some(t)) = (unsafe { c.as_mut() }, unsafe { to.as_mut() }) else {
        return 0;
    };
    if buf.is_null() || cap < MAX_DATAGRAM {
        return 0;
    }
    let out = unsafe { slice::from_raw_parts_mut(buf, cap) };
    match cl.poll_transmit(out, now_us) {
        Some((a, n)) => {
            addr_to(&a, t);
            n
        }
        None => 0,
    }
}

/// When the host should call `vn_client_poll_transmit` next; `UINT64_MAX` if never.
#[no_mangle]
pub unsafe extern "C" fn vn_client_next_deadline(c: *const Client) -> u64 {
    unsafe { c.as_ref() }
        .and_then(|cl| cl.next_deadline())
        .unwrap_or(u64::MAX)
}

/// The next event: 1 and `out` filled, or 0.
#[no_mangle]
pub unsafe extern "C" fn vn_client_poll_event(c: *mut Client, out: *mut VnClientEvent) -> i32 {
    let (Some(cl), Some(o)) = (unsafe { c.as_mut() }, unsafe { out.as_mut() }) else {
        return VN_ERR_INVALID;
    };
    let Some(e) = cl.poll_event() else {
        return 0;
    };
    *o = VnClientEvent {
        kind: 0,
        reason_kind: VN_REASON_NONE,
        reason_code: 0,
        blob_len: 0,
        _reserved: 0,
        caps: 0,
        blob: [0; 32],
    };
    match e {
        ClientEvent::Connected { blob, caps } => {
            o.kind = VN_EVENT_CONNECTED;
            o.caps = caps;
            let b = blob.as_bytes();
            o.blob_len = b.len() as u8;
            for (d, s) in o.blob.iter_mut().zip(b) {
                *d = *s;
            }
        }
        ClientEvent::Failed(Failed::Rejected(code)) => {
            o.kind = VN_EVENT_FAILED;
            o.reason_kind = VN_REASON_REJECTED;
            o.reason_code = code;
        }
        ClientEvent::Failed(Failed::Timeout) => {
            o.kind = VN_EVENT_FAILED;
            o.reason_kind = VN_REASON_NO_ANSWER;
        }
        ClientEvent::Disconnected(r) => {
            o.kind = VN_EVENT_DISCONNECTED;
            (o.reason_kind, o.reason_code) = reason(r);
        }
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn vn_client_send(
    c: *mut Client,
    ch: u8,
    data: *const u8,
    len: usize,
) -> i32 {
    let Some(cl) = (unsafe { c.as_mut() }) else {
        return VN_ERR_INVALID;
    };
    if data.is_null() && len > 0 || len > MSG_MAX {
        return if len > MSG_MAX {
            VN_ERR_TOO_BIG
        } else {
            VN_ERR_INVALID
        };
    }
    let d: &[u8] = if len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(data, len) }
    };
    match cl.send(ch, d) {
        Ok(()) => VN_OK,
        Err(e) => send_code(e),
    }
}

/// The next received message: 1 with channel and length written, bytes in `buf`; or 0.
#[no_mangle]
pub unsafe extern "C" fn vn_client_poll_recv(
    c: *mut Client,
    buf: *mut u8,
    cap: usize,
    ch: *mut u8,
    len: *mut u32,
) -> i32 {
    let (Some(cl), Some(ch_out), Some(len_out)) =
        (unsafe { c.as_mut() }, unsafe { ch.as_mut() }, unsafe {
            len.as_mut()
        })
    else {
        return VN_ERR_INVALID;
    };
    if buf.is_null() || cap < MSG_MAX {
        return VN_ERR_INVALID;
    }
    let b = unsafe { slice::from_raw_parts_mut(buf, cap) };
    match cl.poll_recv(b) {
        Some((channel, n)) => {
            *ch_out = channel;
            *len_out = n as u32;
            1
        }
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn vn_client_disconnect(c: *mut Client, reason: u8) {
    if let Some(cl) = unsafe { c.as_mut() } {
        cl.disconnect(reason);
    }
}

/// 1 if the connection is established, else 0.
#[no_mangle]
pub unsafe extern "C" fn vn_client_is_connected(c: *const Client) -> i32 {
    i32::from(unsafe { c.as_ref() }.is_some_and(|cl| cl.is_connected()))
}

#[no_mangle]
pub unsafe extern "C" fn vn_client_conn_stats(c: *const Client, out: *mut VnConnStats) -> i32 {
    let (Some(cl), Some(o)) = (unsafe { c.as_ref() }, unsafe { out.as_mut() }) else {
        return VN_ERR_INVALID;
    };
    match cl.conn_stats() {
        Some(st) => {
            fill_stats(&st, o);
            VN_OK
        }
        None => VN_ERR_NOT_CONNECTED,
    }
}

// ------------------------------------------------------------------------------ build glue

#[cfg(feature = "abi")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Panics are defects (invariant I4); the build uses panic = "abort".
    loop {}
}

#[cfg(feature = "abi")]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
