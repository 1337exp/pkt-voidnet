#![no_std]

// ABI probe: a no_std staticlib with one C function. If Zig (windows-gnu) links
// and runs it, the Rust side adds no runtime dependency we cannot satisfy.

#[no_mangle]
pub extern "C" fn voidnet_probe_add(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}

// panic = "abort" never unwinds, but precompiled compiler_builtins objects still
// reference the personality symbol; an empty definition satisfies the linker.
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
