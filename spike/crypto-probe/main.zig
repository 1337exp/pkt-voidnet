const std = @import("std");

extern fn vn_probe_sip(key: [*]const u8, data: [*]const u8, len: usize) u64;
extern fn vn_probe_seal(key: [*]const u8, pn: u32, buf: [*]u8, len: usize) i32;
extern fn vn_probe_open(key: [*]const u8, pn: u32, buf: [*]u8, len: usize) i32;

pub fn main() u8 {
    var key: [32]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i);
    const sip_key: *const [16]u8 = key[0..16];

    // SipHash-1-3 must match Zig std (the cookie primitive magnet uses).
    const msg = "hello cookie 123";
    const Sip = std.crypto.auth.siphash.SipHash64(1, 3);
    var mac = Sip.init(sip_key);
    mac.update(msg);
    if (vn_probe_sip(sip_key, msg.ptr, msg.len) != mac.finalInt()) return 1;

    // ChaCha20-Poly1305 must match Zig std byte for byte.
    var buf: [64 + 16]u8 = undefined;
    for (buf[0..64], 0..) |*b, i| b.* = @intCast(i * 3);
    var expected: [64]u8 = buf[0..64].*;
    var tag: [16]u8 = undefined;
    var nonce: [12]u8 = @splat(0);
    std.mem.writeInt(u32, nonce[0..4], 42, .little);
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(&expected, &tag, buf[0..64], "hdr", nonce, key);

    if (vn_probe_seal(&key, 42, &buf, 64) != 0) return 2;
    if (!std.mem.eql(u8, buf[0..64], &expected)) return 3;
    if (!std.mem.eql(u8, buf[64..80], &tag)) return 4;
    if (vn_probe_open(&key, 42, &buf, 64) != 0) return 5;
    for (buf[0..64], 0..) |b, i| if (b != @as(u8, @intCast(i * 3))) return 6;
    // tamper: a flipped bit must fail authentication
    _ = vn_probe_seal(&key, 42, &buf, 64);
    buf[10] ^= 1;
    if (vn_probe_open(&key, 42, &buf, 64) == 0) return 7;
    return 0;
}
