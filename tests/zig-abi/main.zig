// Links the Rust staticlib into a Zig program and checks the ABI entry points.
// Exit code 0 means ok. See scripts in the repository README for the build command.
extern fn vn_abi_version() u32;
extern fn vn_wire_version() u32;

pub fn main() u8 {
    if (vn_abi_version() != 2) return 1;
    if (vn_wire_version() != 1) return 2;
    return 0;
}
