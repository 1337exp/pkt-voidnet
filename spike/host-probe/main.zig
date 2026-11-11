const std = @import("std");

extern fn vn_abi_version() u32;
extern fn vn_server_size() usize;
extern fn vn_server_align() usize;
extern fn vn_server_init(mem: ?[*]u8, len: usize, seed: ?[*]const u8) i32;
extern fn vn_server_magic(srv: [*]const u8) u32;
extern fn vn_server_digest(srv: [*]u8, conn: usize, n: usize) u64;

fn zigDigest(seed: [32]u8, n: usize) u64 {
    var ring: [1024]u8 = undefined;
    const m = if (n < 32) n else 32;
    @memcpy(ring[0..m], seed[0..m]);
    if (n > 32) @memset(ring[32..n], 0xAB);
    var acc: u128 = 0x9E37_79B9_7F4A_7C15_F39C_C060_5CED_C834;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        acc = (acc *% (6364136223846793005 + @as(u128, i))) ^ @as(u128, ring[i]);
    }
    const q = acc / 1_000_000_007;
    const r = acc % 1_000_000_007;
    return @as(u64, @truncate(q ^ (r << 32))) ^ @as(u64, @truncate(q >> 64));
}

// Exit code 0 = all checks passed, otherwise the number of the failed check.
pub fn main() u8 {
    if (vn_abi_version() != 1) return 1;
    const size = vn_server_size();
    const al = vn_server_align();
    if (size == 0 or al == 0) return 2;

    // Host-owned memory: the Zig side allocates, Rust initialises in place.
    const raw = std.heap.page_allocator.alloc(u8, size + al) catch return 3;
    defer std.heap.page_allocator.free(raw);
    const start = std.mem.alignForward(usize, @intFromPtr(raw.ptr), al) - @intFromPtr(raw.ptr);
    const mem = raw[start .. start + size];

    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i * 7 + 1);

    if (vn_server_init(mem.ptr, size - 1, &seed) != -3) return 4; // too small
    if (vn_server_init(mem.ptr + 1, size, &seed) != -2) return 5; // misaligned
    if (vn_server_init(null, size, &seed) != -1) return 6; // null
    if (vn_server_init(mem.ptr, size, &seed) != 0) return 7;
    if (vn_server_magic(mem.ptr) != 0x564E_4554) return 8;

    for ([_]usize{ 0, 5, 32, 33, 700, 1024 }) |n| {
        if (vn_server_digest(mem.ptr, 3, n) != zigDigest(seed, n)) return 9;
    }
    if (vn_server_digest(mem.ptr, 64, 1) != 0) return 10; // out of range conn
    return 0;
}
