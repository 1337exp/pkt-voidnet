#![no_std]

// Spike S1/S2/S3/S4: no_std + no alloc core placed in memory owned by the host,
// u128 arithmetic (compiler-rt symbols), variable-length memcpy/memset.

use core::ptr;

const MAX_CONN: usize = 64;
const RING: usize = 1024;

#[repr(C)]
pub struct Conn {
    used: u8,
    head: u32,
    ring: [u8; RING],
}

#[repr(C)]
pub struct Server {
    magic: u32,
    secret: [u8; 32],
    conns: [Conn; MAX_CONN],
}

const MAGIC: u32 = 0x564E_4554;

#[no_mangle]
pub extern "C" fn vn_abi_version() -> u32 {
    (0 << 16) | 1
}

#[no_mangle]
pub extern "C" fn vn_server_size() -> usize {
    core::mem::size_of::<Server>()
}

#[no_mangle]
pub extern "C" fn vn_server_align() -> usize {
    core::mem::align_of::<Server>()
}

/// 0 ok, -1 null, -2 misaligned, -3 too small.
#[no_mangle]
pub unsafe extern "C" fn vn_server_init(mem: *mut u8, len: usize, seed: *const u8) -> i32 {
    if mem.is_null() || seed.is_null() {
        return -1;
    }
    if (mem as usize) % core::mem::align_of::<Server>() != 0 {
        return -2;
    }
    if len < core::mem::size_of::<Server>() {
        return -3;
    }
    ptr::write_bytes(mem, 0, core::mem::size_of::<Server>());
    let srv = mem as *mut Server;
    (*srv).magic = MAGIC;
    ptr::copy_nonoverlapping(seed, (*srv).secret.as_mut_ptr(), 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn vn_server_magic(srv: *const Server) -> u32 {
    (*srv).magic
}

/// Fill a connection ring with a pattern of variable length (memset/memcpy), return a u128-based digest.
#[no_mangle]
pub unsafe extern "C" fn vn_server_digest(srv: *mut Server, conn: usize, n: usize) -> u64 {
    if conn >= MAX_CONN || n > RING {
        return 0;
    }
    let c = &mut (*srv).conns[conn];
    c.used = 1;
    let secret = (*srv).secret;
    ptr::copy_nonoverlapping(secret.as_ptr(), c.ring.as_mut_ptr(), if n < 32 { n } else { 32 });
    if n > 32 {
        ptr::write_bytes(c.ring.as_mut_ptr().add(32), 0xAB, n - 32);
    }
    let mut acc: u128 = 0x9E37_79B9_7F4A_7C15_F39C_C060_5CED_C834;
    let mut i = 0;
    while i < n {
        acc = acc.wrapping_mul(6364136223846793005u128 + i as u128) ^ (c.ring[i] as u128);
        i += 1;
    }
    let q = acc / 1_000_000_007u128;
    let r = acc % 1_000_000_007u128;
    ((q ^ (r << 32)) as u64) ^ ((q >> 64) as u64)
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
