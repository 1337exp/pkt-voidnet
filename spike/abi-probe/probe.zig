extern fn voidnet_probe_add(a: u32, b: u32) u32;

// Exit code is the proof: 2 + 3 must come back as 5 from the Rust library.
pub fn main() u8 {
    return @intCast(voidnet_probe_add(2, 3));
}
