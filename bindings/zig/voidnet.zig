//! Zig binding for pkt-voidnet. A thin, safe-looking layer over the C ABI in `include/voidnet.h`.
//!
//! The library never allocates: this file asks it how much memory it needs, takes that from a Zig
//! allocator, and gives the block over. Time and entropy are arguments, not hidden calls.
//!
//! Обвязка pkt-voidnet для Zig: тонкий слой над C ABI из `include/voidnet.h`. Библиотека память не
//! выделяет: здесь спрашивают, сколько нужно, берут у аллокатора Zig и отдают блок. Время и
//! энтропия приходят аргументами.

const std = @import("std");

// ------------------------------------------------------------------------------ raw ABI

/// The C functions, exactly as in the header. Prefer the wrappers below.
pub const raw = struct {
    pub extern fn vn_abi_version() u32;
    pub extern fn vn_wire_version() u32;
    pub extern fn vn_abi_info(out: *AbiInfo) i32;

    pub extern fn vn_server_config_default(cfg: *ServerConfigRaw, protocol_id: u64) i32;
    pub extern fn vn_server_size() usize;
    pub extern fn vn_server_align() usize;
    pub extern fn vn_server_init(mem: [*]u8, len: usize, cfg: *const ServerConfigRaw, seed: [*]const u8, now_us: u64) i32;
    pub extern fn vn_server_rotate_secret(s: *anyopaque, fresh16: [*]const u8, now_us: u64) void;
    pub extern fn vn_server_handle_datagram(s: *anyopaque, from: *const Addr, data: [*]const u8, len: usize, now_us: u64) void;
    pub extern fn vn_server_handle_timeout(s: *anyopaque, now_us: u64) void;
    pub extern fn vn_server_next_deadline(s: *const anyopaque) u64;
    pub extern fn vn_server_poll_transmit(s: *anyopaque, buf: [*]u8, cap: usize, to: *Addr, now_us: u64) usize;
    pub extern fn vn_server_poll_event(s: *anyopaque, out: *EventRaw) i32;
    pub extern fn vn_server_send(s: *anyopaque, conn: Conn, ch: u8, data: [*]const u8, len: usize) i32;
    pub extern fn vn_server_flush(s: *anyopaque, conn: Conn) i32;
    pub extern fn vn_server_poll_recv(s: *anyopaque, buf: [*]u8, cap: usize, out: *RecvRaw) i32;
    pub extern fn vn_server_disconnect(s: *anyopaque, conn: Conn, reason: u8) i32;
    pub extern fn vn_server_conn_stats(s: *const anyopaque, conn: Conn, out: *ConnStats) i32;
    pub extern fn vn_server_conn_addr(s: *const anyopaque, conn: Conn, out: *Addr) i32;
    pub extern fn vn_server_stats(s: *const anyopaque, out: *ServerStats) i32;
    pub extern fn vn_server_slots_in_use(s: *const anyopaque) u32;

    pub extern fn vn_client_config_default(cfg: *ClientConfigRaw, protocol_id: u64) i32;
    pub extern fn vn_client_size() usize;
    pub extern fn vn_client_align() usize;
    pub extern fn vn_client_init(mem: [*]u8, len: usize, cfg: *const ClientConfigRaw) i32;
    pub extern fn vn_client_connect(c: *anyopaque, server: *const Addr, random: u64, now_us: u64) i32;
    pub extern fn vn_client_handle_datagram(c: *anyopaque, from: *const Addr, data: [*]const u8, len: usize, now_us: u64) void;
    pub extern fn vn_client_poll_transmit(c: *anyopaque, buf: [*]u8, cap: usize, to: *Addr, now_us: u64) usize;
    pub extern fn vn_client_next_deadline(c: *const anyopaque) u64;
    pub extern fn vn_client_poll_event(c: *anyopaque, out: *ClientEventRaw) i32;
    pub extern fn vn_client_send(c: *anyopaque, ch: u8, data: [*]const u8, len: usize) i32;
    pub extern fn vn_client_flush(c: *anyopaque) i32;
    pub extern fn vn_client_poll_recv(c: *anyopaque, buf: [*]u8, cap: usize, ch: *u8, len: *u32) i32;
    pub extern fn vn_client_disconnect(c: *anyopaque, reason: u8) void;
    pub extern fn vn_client_is_connected(c: *const anyopaque) i32;
    pub extern fn vn_client_conn_stats(c: *const anyopaque, out: *ConnStats) i32;
};

pub const Addr = extern struct {
    len: u8 = 0,
    source_len: u8 = 0,
    bytes: [20]u8 = @splat(0),

    /// An IPv4 endpoint in the recommended 18-byte form (IPv4-mapped IPv6 plus a big-endian port).
    pub fn ipv4(ip: [4]u8, port: u16) Addr {
        var a: Addr = .{ .len = 18, .source_len = 16 };
        a.bytes[10] = 0xFF;
        a.bytes[11] = 0xFF;
        @memcpy(a.bytes[12..16], &ip);
        std.mem.writeInt(u16, a.bytes[16..18], port, .big);
        return a;
    }

    pub fn eql(a: Addr, b: Addr) bool {
        return a.len == b.len and std.mem.eql(u8, a.bytes[0..a.len], b.bytes[0..b.len]);
    }
};

pub const Conn = extern struct { index: u32, generation: u32 };

pub const EventRaw = extern struct {
    kind: u32,
    conn: Conn,
    addr: Addr,
    reason_kind: u8,
    reason_code: u8,
};

pub const RecvRaw = extern struct { conn: Conn, ch: u8, reserved: [3]u8, len: u32 };

pub const ClientEventRaw = extern struct {
    kind: u32,
    reason_kind: u8,
    reason_code: u8,
    blob_len: u8,
    reserved: u8,
    caps: u32,
    blob: [32]u8,
};

pub const ConnStats = extern struct {
    packets_sent: u64,
    packets_recv: u64,
    bytes_sent: u64,
    bytes_recv: u64,
    ack_only_sent: u64,
    packets_lost: u64,
    messages_resent: u64,
    duplicates_dropped: u64,
    refused_capacity: u64,
    probes: u64,
    rtt_us: u64,
    rtt_var_us: u64,
    min_rtt_us: u64,
    latest_rtt_us: u64,
};

pub const ServerStats = extern struct {
    datagrams: u64,
    bytes_in: u64,
    bytes_out: u64,
    parse_errors: u64,
    hello: u64,
    response: u64,
    rate_limited_source: u64,
    rate_limited_global: u64,
    bad_cookie: u64,
    stale_cookie: u64,
    challenges: u64,
    accepted: u64,
    rejected_full: u64,
    deferred_pending: u64,
    confirmed: u64,
    bad_token: u64,
    unknown_peer: u64,
};

pub const ServerConfigRaw = extern struct {
    struct_size: u32,
    app_version: u32,
    protocol_id: u64,
    rotation_interval_us: u64,
    unconfirmed_timeout_us: u64,
    idle_timeout_us: u64,
    max_ack_delay_us: u64,
    keepalive_us: u64,
    initial_rtt_us: u64,
    max_connections: u32,
    max_per_source: u32,
    max_pending_per_source: u32,
    hello_rate_per_s: u32,
    hello_burst: u32,
    global_rate_per_s: u32,
    global_burst: u32,
    cookie_freshness_s: u32,
    max_datagram: u16,
    channel_count: u8,
    blob_len: u8,
    channel_modes: [16]u8,
    blob: [32]u8,
};

pub const ClientConfigRaw = extern struct {
    struct_size: u32,
    app_version: u32,
    protocol_id: u64,
    retry_interval_us: u64,
    handshake_timeout_us: u64,
    idle_timeout_us: u64,
    max_ack_delay_us: u64,
    keepalive_us: u64,
    initial_rtt_us: u64,
    max_datagram: u16,
    channel_count: u8,
    response_retries: u8,
    channel_modes: [16]u8,
};

pub const AbiInfo = extern struct {
    abi_version: u32,
    wire_version: u32,
    sizeof_addr: u32,
    sizeof_conn: u32,
    sizeof_event: u32,
    sizeof_recv: u32,
    sizeof_client_event: u32,
    sizeof_conn_stats: u32,
    sizeof_server_stats: u32,
    sizeof_server_config: u32,
    sizeof_client_config: u32,
    msg_max: u32,
    max_datagram: u32,
    server_slots: u32,
    max_channels: u32,
};

// ------------------------------------------------------------------------------ safe layer

pub const Mode = enum(u8) { unreliable = 0, unreliable_sequenced = 1, reliable_ordered = 2 };

pub const Error = error{
    Invalid,
    Full,
    TooBig,
    NoChannel,
    NotConnected,
    NoMem,
    Align,
    Config,
    Version,
    Unknown,
};

fn check(rc: i32) Error!void {
    return switch (rc) {
        0 => {},
        -1 => error.Invalid,
        -2 => error.Full,
        -3 => error.TooBig,
        -4 => error.NoChannel,
        -5 => error.NotConnected,
        -6 => error.NoMem,
        -7 => error.Align,
        -8 => error.Config,
        -9 => error.Version,
        else => error.Unknown,
    };
}

/// Check that the struct definitions in this file match the library that is linked in.
/// Call it once at start-up; a mismatch means the header and the library are from different builds.
pub fn checkAbi() Error!AbiInfo {
    var info: AbiInfo = undefined;
    try check(raw.vn_abi_info(&info));
    if (info.sizeof_addr != @sizeOf(Addr) or info.sizeof_conn != @sizeOf(Conn) or
        info.sizeof_event != @sizeOf(EventRaw) or info.sizeof_recv != @sizeOf(RecvRaw) or
        info.sizeof_client_event != @sizeOf(ClientEventRaw) or info.sizeof_conn_stats != @sizeOf(ConnStats) or
        info.sizeof_server_stats != @sizeOf(ServerStats) or info.sizeof_server_config != @sizeOf(ServerConfigRaw) or
        info.sizeof_client_config != @sizeOf(ClientConfigRaw)) return error.Version;
    return info;
}

pub const Reason = union(enum) {
    local: u8,
    remote: u8,
    timeout,
    replaced,

    fn fromRaw(kind: u8, code: u8) Reason {
        return switch (kind) {
            1 => .{ .local = code },
            2 => .{ .remote = code },
            4 => .replaced,
            else => .timeout,
        };
    }
};

pub const Event = union(enum) {
    connected: struct { conn: Conn, addr: Addr },
    disconnected: struct { conn: Conn, reason: Reason },
};

pub const Received = struct { conn: Conn, ch: u8, len: usize };

pub const ServerConfig = struct {
    protocol_id: u64,
    app_version: u32 = 0,
    channels: []const Mode,
    /// Application data every client gets in ACCEPT (at most 32 bytes), for example game parameters.
    accept_blob: []const u8 = "",
    /// 0 means all slots of the build.
    max_connections: u32 = 0,
    /// All connections from one source. `null` means no limit (LAN, NAT).
    max_per_source: ?u32 = null,
    max_pending_per_source: ?u32 = null,
    max_ack_delay_us: ?u64 = null,
    idle_timeout_us: ?u64 = null,
    hello_burst: ?u32 = null,

    fn toRaw(self: ServerConfig) Error!ServerConfigRaw {
        var c: ServerConfigRaw = undefined;
        try check(raw.vn_server_config_default(&c, self.protocol_id));
        if (self.channels.len > 16 or self.accept_blob.len > 32) return error.Config;
        c.app_version = self.app_version;
        c.channel_count = @intCast(self.channels.len);
        for (self.channels, 0..) |m, i| c.channel_modes[i] = @intFromEnum(m);
        c.blob_len = @intCast(self.accept_blob.len);
        @memcpy(c.blob[0..self.accept_blob.len], self.accept_blob);
        c.max_connections = self.max_connections;
        c.max_per_source = self.max_per_source orelse 0xFFFF_FFFF;
        if (self.max_pending_per_source) |v| c.max_pending_per_source = v;
        if (self.max_ack_delay_us) |v| c.max_ack_delay_us = v;
        if (self.idle_timeout_us) |v| c.idle_timeout_us = v;
        if (self.hello_burst) |v| c.hello_burst = v;
        return c;
    }
};

pub const ClientConfig = struct {
    protocol_id: u64,
    app_version: u32 = 0,
    channels: []const Mode,
    max_ack_delay_us: ?u64 = null,
    idle_timeout_us: ?u64 = null,

    fn toRaw(self: ClientConfig) Error!ClientConfigRaw {
        var c: ClientConfigRaw = undefined;
        try check(raw.vn_client_config_default(&c, self.protocol_id));
        if (self.channels.len > 16) return error.Config;
        c.app_version = self.app_version;
        c.channel_count = @intCast(self.channels.len);
        for (self.channels, 0..) |m, i| c.channel_modes[i] = @intFromEnum(m);
        if (self.max_ack_delay_us) |v| c.max_ack_delay_us = v;
        if (self.idle_timeout_us) |v| c.idle_timeout_us = v;
        return c;
    }
};

/// Memory for one library object, taken from a Zig allocator and aligned by hand.
const Block = struct {
    raw_mem: []u8,
    start: [*]u8,

    fn alloc(allocator: std.mem.Allocator, size: usize, alignment: usize) !Block {
        const mem = try allocator.alloc(u8, size + alignment);
        const addr = std.mem.alignForward(usize, @intFromPtr(mem.ptr), alignment);
        return .{ .raw_mem = mem, .start = @ptrFromInt(addr) };
    }
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    block: Block,
    ptr: *anyopaque,

    /// `seed` is 32 fresh random bytes from the operating system.
    pub fn init(allocator: std.mem.Allocator, cfg: ServerConfig, seed: [32]u8, now_us: u64) !Server {
        const size = raw.vn_server_size();
        const block = try Block.alloc(allocator, size, raw.vn_server_align());
        errdefer allocator.free(block.raw_mem);
        const c = try cfg.toRaw();
        try check(raw.vn_server_init(block.start, size, &c, &seed, now_us));
        return .{ .allocator = allocator, .block = block, .ptr = block.start };
    }

    pub fn deinit(self: *Server) void {
        // the library holds nothing outside the block, so freeing it is all there is to do
        @memset(self.block.raw_mem, 0xDD);
        self.allocator.free(self.block.raw_mem);
        self.* = undefined;
    }

    pub fn rotateSecret(self: *Server, fresh: [16]u8, now_us: u64) void {
        raw.vn_server_rotate_secret(self.ptr, &fresh, now_us);
    }

    pub fn handleDatagram(self: *Server, from: Addr, data: []const u8, now_us: u64) void {
        raw.vn_server_handle_datagram(self.ptr, &from, data.ptr, data.len, now_us);
    }

    pub fn handleTimeout(self: *Server, now_us: u64) void {
        raw.vn_server_handle_timeout(self.ptr, now_us);
    }

    pub fn nextDeadline(self: *const Server) ?u64 {
        const d = raw.vn_server_next_deadline(self.ptr);
        return if (d == std.math.maxInt(u64)) null else d;
    }

    /// The next datagram to send, written into `buf` (at least 1400 bytes).
    pub fn pollTransmit(self: *Server, buf: []u8, now_us: u64) ?struct { to: Addr, len: usize } {
        var to: Addr = .{};
        const n = raw.vn_server_poll_transmit(self.ptr, buf.ptr, buf.len, &to, now_us);
        return if (n == 0) null else .{ .to = to, .len = n };
    }

    pub fn pollEvent(self: *Server) ?Event {
        var e: EventRaw = undefined;
        if (raw.vn_server_poll_event(self.ptr, &e) != 1) return null;
        return switch (e.kind) {
            1 => .{ .connected = .{ .conn = e.conn, .addr = e.addr } },
            else => .{ .disconnected = .{ .conn = e.conn, .reason = Reason.fromRaw(e.reason_kind, e.reason_code) } },
        };
    }

    /// Queue a message. Nothing leaves until `flush` or a timer starts a datagram.
    pub fn send(self: *Server, conn: Conn, ch: u8, data: []const u8) Error!void {
        try check(raw.vn_server_send(self.ptr, conn, ch, data.ptr, data.len));
    }

    /// Send what is queued for `conn` now (the next `pollTransmit` calls return the datagrams).
    /// Does nothing if nothing is queued.
    pub fn flush(self: *Server, conn: Conn) Error!void {
        try check(raw.vn_server_flush(self.ptr, conn));
    }

    /// The next received message, bytes written into `buf` (at least 1200).
    pub fn pollRecv(self: *Server, buf: []u8) ?Received {
        var r: RecvRaw = undefined;
        if (raw.vn_server_poll_recv(self.ptr, buf.ptr, buf.len, &r) != 1) return null;
        return .{ .conn = r.conn, .ch = r.ch, .len = r.len };
    }

    pub fn disconnect(self: *Server, conn: Conn, reason: u8) Error!void {
        try check(raw.vn_server_disconnect(self.ptr, conn, reason));
    }

    pub fn connStats(self: *const Server, conn: Conn) ?ConnStats {
        var s: ConnStats = undefined;
        return if (raw.vn_server_conn_stats(self.ptr, conn, &s) == 0) s else null;
    }

    pub fn connAddr(self: *const Server, conn: Conn) ?Addr {
        var a: Addr = undefined;
        return if (raw.vn_server_conn_addr(self.ptr, conn, &a) == 0) a else null;
    }

    pub fn stats(self: *const Server) ServerStats {
        var s: ServerStats = undefined;
        _ = raw.vn_server_stats(self.ptr, &s);
        return s;
    }

    pub fn slotsInUse(self: *const Server) u32 {
        return raw.vn_server_slots_in_use(self.ptr);
    }
};

pub const Failure = union(enum) { rejected: u8, no_answer };

pub const ClientEvent = union(enum) {
    connected: struct { blob: [32]u8, blob_len: u8, caps: u32 },
    failed: Failure,
    disconnected: Reason,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    block: Block,
    ptr: *anyopaque,

    pub fn init(allocator: std.mem.Allocator, cfg: ClientConfig) !Client {
        const size = raw.vn_client_size();
        const block = try Block.alloc(allocator, size, raw.vn_client_align());
        errdefer allocator.free(block.raw_mem);
        const c = try cfg.toRaw();
        try check(raw.vn_client_init(block.start, size, &c));
        return .{ .allocator = allocator, .block = block, .ptr = block.start };
    }

    pub fn deinit(self: *Client) void {
        @memset(self.block.raw_mem, 0xDD);
        self.allocator.free(self.block.raw_mem);
        self.* = undefined;
    }

    /// `random` is 8 fresh random bytes from the operating system.
    pub fn connect(self: *Client, server: Addr, random: u64, now_us: u64) Error!void {
        try check(raw.vn_client_connect(self.ptr, &server, random, now_us));
    }

    pub fn handleDatagram(self: *Client, from: Addr, data: []const u8, now_us: u64) void {
        raw.vn_client_handle_datagram(self.ptr, &from, data.ptr, data.len, now_us);
    }

    pub fn pollTransmit(self: *Client, buf: []u8, now_us: u64) ?struct { to: Addr, len: usize } {
        var to: Addr = .{};
        const n = raw.vn_client_poll_transmit(self.ptr, buf.ptr, buf.len, &to, now_us);
        return if (n == 0) null else .{ .to = to, .len = n };
    }

    pub fn nextDeadline(self: *const Client) ?u64 {
        const d = raw.vn_client_next_deadline(self.ptr);
        return if (d == std.math.maxInt(u64)) null else d;
    }

    pub fn pollEvent(self: *Client) ?ClientEvent {
        var e: ClientEventRaw = undefined;
        if (raw.vn_client_poll_event(self.ptr, &e) != 1) return null;
        return switch (e.kind) {
            1 => .{ .connected = .{ .blob = e.blob, .blob_len = e.blob_len, .caps = e.caps } },
            3 => .{ .failed = if (e.reason_kind == 5) .{ .rejected = e.reason_code } else .no_answer },
            else => .{ .disconnected = Reason.fromRaw(e.reason_kind, e.reason_code) },
        };
    }

    /// Queue a message; see `Server.send`.
    pub fn send(self: *Client, ch: u8, data: []const u8) Error!void {
        try check(raw.vn_client_send(self.ptr, ch, data.ptr, data.len));
    }

    /// Send what is queued now; see `Server.flush`.
    pub fn flush(self: *Client) Error!void {
        try check(raw.vn_client_flush(self.ptr));
    }

    pub fn pollRecv(self: *Client, buf: []u8) ?struct { ch: u8, len: usize } {
        var ch: u8 = undefined;
        var len: u32 = undefined;
        if (raw.vn_client_poll_recv(self.ptr, buf.ptr, buf.len, &ch, &len) != 1) return null;
        return .{ .ch = ch, .len = len };
    }

    pub fn disconnect(self: *Client, reason: u8) void {
        raw.vn_client_disconnect(self.ptr, reason);
    }

    pub fn isConnected(self: *const Client) bool {
        return raw.vn_client_is_connected(self.ptr) == 1;
    }

    pub fn connStats(self: *const Client) ?ConnStats {
        var s: ConnStats = undefined;
        return if (raw.vn_client_conn_stats(self.ptr, &s) == 0) s else null;
    }
};
