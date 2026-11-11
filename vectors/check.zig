// Independent check of vectors/wire-v1.txt: a second implementation written from
// docs/wire.md alone, in another language, without looking at the Rust code.
// If it prints a different description for any line, the document or one of the
// implementations is wrong.
//
// Run:  zig test vectors/check.zig
//
// Независимая проверка vectors/wire-v1.txt: вторая реализация, написанная только по
// docs/wire.md, на другом языке, без чтения кода на Rust. Если она печатает другое
// описание хотя бы для одной строки, неверен документ или одна из реализаций.

const std = @import("std");

const vectors = @embedFile("wire-v1.txt");

const Mode = enum { reliable_ordered, unreliable, sequenced };

// the channel table fixed in the header of wire-v1.txt
const channels = [_]Mode{ .reliable_ordered, .unreliable, .sequenced };

const max_datagram = 1400;

const Out = struct {
    buf: [8192]u8 = undefined,
    len: usize = 0,

    fn print(self: *Out, comptime fmt: []const u8, args: anytype) !void {
        const s = try std.fmt.bufPrint(self.buf[self.len..], fmt, args);
        self.len += s.len;
    }

    fn hex(self: *Out, bytes: []const u8) !void {
        if (bytes.len == 0) return self.print("-", .{});
        for (bytes) |b| try self.print("{x:0>2}", .{b});
    }

    fn str(self: *const Out) []const u8 {
        return self.buf[0..self.len];
    }
};

const R = struct {
    b: []const u8,
    p: usize = 0,

    fn left(self: *const R) usize {
        return self.b.len - self.p;
    }

    fn bytes(self: *R, n: usize) ![]const u8 {
        if (n > self.left()) return error.Drop;
        const s = self.b[self.p .. self.p + n];
        self.p += n;
        return s;
    }

    fn u8_(self: *R) !u8 {
        return (try self.bytes(1))[0];
    }

    fn u16_(self: *R) !u16 {
        return std.mem.readInt(u16, (try self.bytes(2))[0..2], .little);
    }

    fn u32_(self: *R) !u32 {
        return std.mem.readInt(u32, (try self.bytes(4))[0..4], .little);
    }

    fn u64_(self: *R) !u64 {
        return std.mem.readInt(u64, (try self.bytes(8))[0..8], .little);
    }

    fn varint(self: *R) !u32 {
        var v: u32 = 0;
        var i: usize = 0;
        while (i < 5) : (i += 1) {
            const b = try self.u8_();
            if (i == 4 and b > 0x0f) return error.Drop;
            v |= @as(u32, b & 0x7f) << @intCast(7 * i);
            if (b & 0x80 == 0) {
                if (i > 0 and b == 0) return error.Drop; // not canonical
                return v;
            }
        }
        return error.Drop;
    }

    fn zeroRest(self: *R) !void {
        for (self.b[self.p..]) |b| if (b != 0) return error.Drop;
        self.p = self.b.len;
    }
};

fn helloFields(r: *R, out: *Out) !void {
    const ver = try r.u8_();
    const proto = try r.u64_();
    const app = try r.u32_();
    const cfg = try r.u32_();
    const rnd = try r.u64_();
    const caps = try r.u32_();
    try out.print("ver={d} proto={x:0>16} app={d} cfg={x:0>8} rnd={x:0>16} caps={x:0>8}", .{ ver, proto, app, cfg, rnd, caps });
}

fn ackFrame(r: *R, out: *Out) !void {
    const largest = try r.u16_();
    const delay = try r.varint();
    const n = try r.u8_();
    if (n > 15) return error.Drop;
    const first = try r.varint();
    if (first == 0) return error.Drop;
    try out.print("; ACK largest={d} delay={d} first={d} ranges=", .{ largest, delay, first });
    var span: u64 = first;
    if (n == 0) try out.print("-", .{});
    var i: u8 = 0;
    while (i < n) : (i += 1) {
        const gap = try r.varint();
        const len = try r.varint();
        if (gap == 0 or len == 0) return error.Drop;
        span += @as(u64, gap) + len;
        if (i > 0) try out.print(",", .{});
        try out.print("{d}/{d}", .{ gap, len });
    }
    if (span > 32768) return error.Drop;
}

fn decode(d: []const u8, out: *Out) !void {
    if (d.len == 0 or d.len > max_datagram) return error.Drop;
    var r = R{ .b = d };
    switch (try r.u8_()) {
        0x00 => {
            if (d.len <= 11) return error.Drop;
            const token = try r.u64_();
            const pn = try r.u16_();
            try out.print("DATA token={x:0>16} pn={d}", .{ token, pn });
            var count: usize = 0;
            var seen_ping = false;
            var seen_disc = false;
            while (r.left() > 0) : (count += 1) {
                if (seen_disc) return error.Drop;
                const tag = try r.u8_();
                switch (tag) {
                    0x00...0x0f => {
                        if (tag >= channels.len) return error.Drop;
                        try out.print("; MSG ch={d} ", .{tag});
                        if (channels[tag] != .unreliable) try out.print("mseq={d} ", .{try r.u16_()});
                        const len = try r.varint();
                        const payload = try r.bytes(len);
                        try out.print("len={d} data=", .{len});
                        try out.hex(payload);
                    },
                    0x10 => {
                        if (count != 0) return error.Drop;
                        try ackFrame(&r, out);
                    },
                    0x11 => {
                        if (seen_ping) return error.Drop;
                        seen_ping = true;
                        try out.print("; PING", .{});
                    },
                    0x12 => {
                        seen_disc = true;
                        try out.print("; DISC reason={d}", .{try r.u8_()});
                    },
                    else => return error.Drop,
                }
            }
        },
        0x80 => {
            if (d.len != 64) return error.Drop;
            try out.print("HELLO ", .{});
            try helloFields(&r, out);
            try r.zeroRest();
        },
        0x81 => {
            if (d.len != 13) return error.Drop;
            const coarse = try r.u32_();
            const cookie = try r.u64_();
            try out.print("CHALLENGE coarse={d} cookie={x:0>16}", .{ coarse, cookie });
        },
        0x82 => {
            if (d.len != 64) return error.Drop;
            const coarse = try r.u32_();
            const cookie = try r.u64_();
            try out.print("RESPONSE coarse={d} cookie={x:0>16} ", .{ coarse, cookie });
            try helloFields(&r, out);
            try r.zeroRest();
        },
        0x83 => {
            const token = try r.u64_();
            const echo = try r.u64_();
            const caps = try r.u32_();
            const blob_len = try r.u8_();
            if (blob_len > 32 or r.left() != blob_len) return error.Drop;
            try out.print("ACCEPT token={x:0>16} echo={x:0>16} caps={x:0>8} blob=", .{ token, echo, caps });
            try out.hex(try r.bytes(blob_len));
        },
        0x84 => {
            if (d.len != 10) return error.Drop;
            const code = try r.u8_();
            const echo = try r.u64_();
            try out.print("REJECT code={d} echo={x:0>16}", .{ code, echo });
        },
        else => return error.Drop,
    }
}

test "every vector decodes to the listed description" {
    var failures: usize = 0;
    var checked: usize = 0;
    var lines = std.mem.splitScalar(u8, vectors, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0 or line[0] == '#') continue;

        var fields = std.mem.splitScalar(u8, line, '\t');
        const name = fields.next() orelse return error.BadVectorLine;
        const hex = fields.next() orelse return error.BadVectorLine;
        const expected = fields.next() orelse return error.BadVectorLine;

        var raw: [max_datagram + 16]u8 = undefined;
        const bytes: []const u8 = if (std.mem.eql(u8, hex, "-")) raw[0..0] else try std.fmt.hexToBytes(&raw, hex);

        var out = Out{};
        const got: []const u8 = if (decode(bytes, &out)) |_| out.str() else |_| "drop";
        checked += 1;
        if (!std.mem.eql(u8, got, expected)) {
            failures += 1;
            std.debug.print("MISMATCH {s}\n  expected: {s}\n  got:      {s}\n", .{ name, expected, got });
        }
    }
    try std.testing.expect(checked >= 50);
    try std.testing.expectEqual(@as(usize, 0), failures);
}
