//! Tests of the Zig binding against the real library: the whole thing through the C ABI, with a
//! small lossy in-process network written here in Zig.
//!
//! Run:  zig build test -Dvoidnet-lib=<path to libvoidnet_ffi.a> -Dtarget=x86_64-windows-gnu
//!
//! Тесты обвязки Zig на настоящей библиотеке: всё через C ABI, с маленькой сетью с потерями,
//! написанной здесь же на Zig.

const std = @import("std");
const vn = @import("voidnet.zig");

const PID: u64 = 0x5445_4501;
const channels = [_]vn.Mode{ .reliable_ordered, .unreliable, .unreliable_sequenced };

// ------------------------------------------------------------------------------ a tiny network

const Packet = struct {
    used: bool = false,
    at: u64 = 0,
    len: u16 = 0,
    data: [1500]u8 = undefined,
};

const Link = struct {
    q: [256]Packet = @splat(.{}),
    rng: u64,
    loss_permille: u64,
    latency_us: u64,

    fn rand(self: *Link) u64 {
        // xorshift64*
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        return self.rng *% 0x2545_F491_4F6C_DD1D;
    }

    fn send(self: *Link, now: u64, data: []const u8) void {
        if (self.rand() % 1000 < self.loss_permille) return;
        for (&self.q) |*p| {
            if (p.used) continue;
            p.used = true;
            p.at = now + self.latency_us + self.rand() % 6_000; // jitter reorders a little
            p.len = @intCast(data.len);
            @memcpy(p.data[0..data.len], data);
            return;
        }
    }

    fn poll(self: *Link, now: u64, out: []u8) ?usize {
        var best: ?*Packet = null;
        for (&self.q) |*p| {
            if (!p.used or p.at > now) continue;
            if (best == null or p.at < best.?.at) best = p;
        }
        const p = best orelse return null;
        p.used = false;
        @memcpy(out[0..p.len], p.data[0..p.len]);
        return p.len;
    }
};

const Peer = struct {
    client: vn.Client,
    addr: vn.Addr,
    up: Link,
    down: Link,
    conn: ?vn.Conn = null,
    connected: bool = false,
    log: [16]vn.ClientEvent = undefined,
    log_len: usize = 0,
};

const World = struct {
    now: u64 = 1_000_000_000,
    server: vn.Server,
    server_addr: vn.Addr,
    peers: []Peer,
    allocator: std.mem.Allocator,
    log: [64]vn.Event = undefined,
    log_len: usize = 0,

    fn init(allocator: std.mem.Allocator, n: usize, loss_permille: u64) !World {
        var server = try vn.Server.init(allocator, .{
            .protocol_id = PID,
            .channels = &channels,
            .accept_blob = "tick=50",
            .hello_burst = 50,
        }, @splat(7), 1_000_000_000);
        errdefer server.deinit();
        const peers = try allocator.alloc(Peer, n);
        errdefer allocator.free(peers);
        var made: usize = 0;
        errdefer for (peers[0..made]) |*p| p.client.deinit();
        for (peers, 0..) |*p, i| {
            p.* = .{
                .client = try vn.Client.init(allocator, .{ .protocol_id = PID, .channels = &channels }),
                .addr = vn.Addr.ipv4(.{ 10, 0, 0, @intCast(i + 1) }, @intCast(5000 + i)),
                .up = .{ .rng = 0x1234 + i * 77, .loss_permille = loss_permille, .latency_us = 15_000 },
                .down = .{ .rng = 0x9999 + i * 31, .loss_permille = loss_permille, .latency_us = 15_000 },
            };
            made += 1;
        }
        const w: World = .{
            .server = server,
            .server_addr = vn.Addr.ipv4(.{ 10, 255, 255, 1 }, 7000),
            .peers = peers,
            .allocator = allocator,
        };
        for (w.peers, 0..) |*p, i| try p.client.connect(w.server_addr, 0xC0FFEE00 + i, w.now);
        return w;
    }

    fn deinit(self: *World) void {
        for (self.peers) |*p| p.client.deinit();
        self.allocator.free(self.peers);
        self.server.deinit();
    }

    fn step(self: *World) void {
        self.now += 1_000;
        var buf: [1500]u8 = undefined;
        for (self.peers) |*p| {
            while (p.up.poll(self.now, &buf)) |n| self.server.handleDatagram(p.addr, buf[0..n], self.now);
            while (p.down.poll(self.now, &buf)) |n| p.client.handleDatagram(self.server_addr, buf[0..n], self.now);
        }
        self.server.handleTimeout(self.now);
        while (self.server.pollTransmit(&buf, self.now)) |t| {
            for (self.peers) |*p| {
                if (p.addr.eql(t.to)) p.down.send(self.now, buf[0..t.len]);
            }
        }
        for (self.peers) |*p| {
            while (p.client.pollTransmit(&buf, self.now)) |t| p.up.send(self.now, buf[0..t.len]);
            while (p.client.pollEvent()) |e| {
                if (p.log_len < p.log.len) {
                    p.log[p.log_len] = e;
                    p.log_len += 1;
                }
                switch (e) {
                    .connected => p.connected = true,
                    else => {},
                }
            }
        }
        while (self.server.pollEvent()) |e| {
            if (self.log_len < self.log.len) {
                self.log[self.log_len] = e;
                self.log_len += 1;
            }
            switch (e) {
                .connected => |c| for (self.peers) |*p| {
                    if (p.addr.eql(c.addr)) p.conn = c.conn;
                },
                .disconnected => {},
            }
        }
    }

    fn runFor(self: *World, us: u64) void {
        const end = self.now + us;
        while (self.now < end) self.step();
    }

    fn allConnected(self: *const World) bool {
        for (self.peers) |p| if (!p.connected or p.conn == null) return false;
        return true;
    }
};

// ------------------------------------------------------------------------------ the tests

test "the struct definitions match the linked library" {
    const info = try vn.checkAbi();
    try std.testing.expectEqual(@as(u32, 1), info.wire_version);
    try std.testing.expectEqual(@as(u32, 1200), info.msg_max);
    try std.testing.expect(info.server_slots >= 4);
}

test "invalid configurations are refused with an error, not a crash" {
    const a = std.testing.allocator;
    // a channel table longer than the library allows
    const too_many: [17]vn.Mode = @splat(.unreliable);
    try std.testing.expectError(error.Config, vn.Server.init(a, .{ .protocol_id = PID, .channels = &too_many }, @splat(1), 0));
    // more reliable channels than this build keeps state for
    const three_reliable = [_]vn.Mode{ .reliable_ordered, .reliable_ordered, .reliable_ordered };
    try std.testing.expectError(error.Config, vn.Server.init(a, .{ .protocol_id = PID, .channels = &three_reliable }, @splat(1), 0));
    try std.testing.expectError(error.Config, vn.Client.init(a, .{ .protocol_id = PID, .channels = &three_reliable }));
    // a blob over 32 bytes
    const long_blob: [33]u8 = @splat('x');
    try std.testing.expectError(error.Config, vn.Server.init(a, .{ .protocol_id = PID, .channels = &channels, .accept_blob = &long_blob }, @splat(1), 0));
}

test "memory taken from a Zig allocator is all the library ever uses" {
    // std.testing.allocator fails the test on a leak, so init and deinit three times
    for (0..3) |_| {
        var s = try vn.Server.init(std.testing.allocator, .{ .protocol_id = PID, .channels = &channels }, @splat(3), 0);
        s.deinit();
        var c = try vn.Client.init(std.testing.allocator, .{ .protocol_id = PID, .channels = &channels });
        c.deinit();
    }
}

test "three clients connect over a lossy network and exchange all three kinds of message" {
    var w = try World.init(std.testing.allocator, 3, 120);
    defer w.deinit();

    var guard: u32 = 0;
    while (!w.allConnected() and guard < 10_000) : (guard += 1) w.step();
    try std.testing.expect(w.allConnected());
    try std.testing.expectEqual(@as(u32, 3), w.server.slotsInUse());

    // the blob from ACCEPT arrived: look at a fresh client event is gone already, check stats instead
    var sent: [3]u32 = @splat(0);
    var got: [3]u32 = @splat(0);
    var inputs_at_server: u32 = 0;
    var buf: [1200]u8 = undefined;
    var tick: u32 = 0;
    while (tick < 8_000) : (tick += 1) {
        for (w.peers, 0..) |*p, i| {
            const conn = p.conn.?;
            // numbered reliable messages from the server, as far as the window allows
            while (sent[i] < 50) {
                var msg: [8]u8 = undefined;
                std.mem.writeInt(u32, msg[0..4], sent[i], .little);
                std.mem.writeInt(u32, msg[4..8], @intCast(i), .little);
                w.server.send(conn, 0, &msg) catch |err| switch (err) {
                    error.Full => break,
                    else => return err,
                };
                sent[i] += 1;
            }
            // an input-like message from the client
            if (tick % 20 == 0) p.client.send(1, "input") catch {};
            // and a state-like one from the server
            if (tick % 20 == 0) w.server.send(conn, 2, "state") catch {};
            // nothing leaves without a flush: one per tick for each side, as a game would do
            p.client.flush() catch {};
            w.server.flush(conn) catch {};
            while (p.client.pollRecv(&buf)) |m| {
                if (m.ch == 0) {
                    const n = std.mem.readInt(u32, buf[0..4], .little);
                    try std.testing.expectEqual(got[i], n); // exact order, no gap, no repeat
                    try std.testing.expectEqual(@as(u32, @intCast(i)), std.mem.readInt(u32, buf[4..8], .little));
                    got[i] += 1;
                }
            }
        }
        while (w.server.pollRecv(&buf)) |m| {
            try std.testing.expectEqual(@as(u8, 1), m.ch);
            inputs_at_server += 1;
        }
        w.step();
    }
    for (got) |g| try std.testing.expectEqual(@as(u32, 50), g);
    try std.testing.expect(inputs_at_server > 100);

    // the server measured a round trip: 15 ms each way plus up to 6 ms of jitter
    for (w.peers) |*p| {
        const s = w.server.connStats(p.conn.?).?;
        try std.testing.expect(s.rtt_us >= 28_000 and s.rtt_us <= 80_000);
        try std.testing.expect(s.packets_lost > 0 or s.packets_recv > 0);
        const cs = p.client.connStats().?;
        try std.testing.expect(cs.rtt_us > 0);
    }
    const ss = w.server.stats();
    try std.testing.expectEqual(@as(u64, 3), ss.confirmed);
}

test "leaving and being thrown out both reach the other side with their reasons" {
    var w = try World.init(std.testing.allocator, 2, 0);
    defer w.deinit();
    var guard: u32 = 0;
    while (!w.allConnected() and guard < 5_000) : (guard += 1) w.step();
    try std.testing.expect(w.allConnected());

    // the client leaves with reason 5: the server's host is told, with the reason
    w.peers[0].client.disconnect(5);
    w.runFor(300_000);
    var saw_remote_5 = false;
    for (w.log[0..w.log_len]) |e| switch (e) {
        .disconnected => |d| switch (d.reason) {
            .remote => |code| saw_remote_5 = saw_remote_5 or code == 5,
            else => {},
        },
        else => {},
    };
    try std.testing.expect(saw_remote_5);
    try std.testing.expectEqual(@as(u32, 1), w.server.slotsInUse());

    // the server throws the other one out with reason 9: that client is told, and the handle is stale
    const conn = w.peers[1].conn.?;
    try w.server.disconnect(conn, 9);
    try std.testing.expectError(error.NotConnected, w.server.send(conn, 0, "late"));
    try std.testing.expectEqual(@as(u32, 0), w.server.slotsInUse());
    w.runFor(300_000);
    var client_saw_9 = false;
    for (w.peers[1].log[0..w.peers[1].log_len]) |e| switch (e) {
        .disconnected => |r| switch (r) {
            .remote => |code| client_saw_9 = client_saw_9 or code == 9,
            else => {},
        },
        else => {},
    };
    try std.testing.expect(client_saw_9);
    try std.testing.expect(!w.peers[1].client.isConnected());
}

test "a client with a different protocol id is told no" {
    const a = std.testing.allocator;
    var s = try vn.Server.init(a, .{ .protocol_id = PID, .channels = &channels }, @splat(5), 1_000_000_000);
    defer s.deinit();
    var c = try vn.Client.init(a, .{ .protocol_id = PID + 1, .channels = &channels });
    defer c.deinit();
    const sa = vn.Addr.ipv4(.{ 10, 255, 255, 1 }, 7000);
    const ca = vn.Addr.ipv4(.{ 10, 0, 0, 9 }, 5000);
    try c.connect(sa, 1, 1_000_000_000);
    var buf: [1500]u8 = undefined;
    var now: u64 = 1_000_000_000;
    var failure: ?vn.Failure = null;
    var steps: u32 = 0;
    while (steps < 200 and failure == null) : (steps += 1) {
        now += 1_000;
        while (c.pollTransmit(&buf, now)) |t| s.handleDatagram(ca, buf[0..t.len], now);
        while (s.pollTransmit(&buf, now)) |t| c.handleDatagram(sa, buf[0..t.len], now);
        while (c.pollEvent()) |e| switch (e) {
            .failed => |f| failure = f,
            else => {},
        };
    }
    try std.testing.expect(failure != null);
    try std.testing.expectEqual(@as(u8, 1), failure.?.rejected); // 1 = version
}
