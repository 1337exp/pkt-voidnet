#![no_std]

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use core::hash::Hasher;
use siphasher::sip::SipHasher13;

/// SipHash-1-3 64-bit over data (cookie primitive).
#[no_mangle]
pub unsafe extern "C" fn vn_probe_sip(key: *const u8, data: *const u8, len: usize) -> u64 {
    let k = core::slice::from_raw_parts(key, 16);
    let k0 = u64::from_le_bytes(k[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(k[8..16].try_into().unwrap());
    let mut h = SipHasher13::new_with_keys(k0, k1);
    h.write(core::slice::from_raw_parts(data, len));
    h.finish()
}

/// Seal `len` bytes in place; writes 16-byte tag after the data. Returns 0 on ok.
#[no_mangle]
pub unsafe extern "C" fn vn_probe_seal(key: *const u8, pn: u32, buf: *mut u8, len: usize) -> i32 {
    let cipher = ChaCha20Poly1305::new(core::slice::from_raw_parts(key, 32).into());
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&pn.to_le_bytes());
    let data = core::slice::from_raw_parts_mut(buf, len);
    match cipher.encrypt_in_place_detached(Nonce::from_slice(&nonce), b"hdr", data) {
        Ok(tag) => {
            core::ptr::copy_nonoverlapping(tag.as_ptr(), buf.add(len), 16);
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn vn_probe_open(key: *const u8, pn: u32, buf: *mut u8, len: usize) -> i32 {
    let cipher = ChaCha20Poly1305::new(core::slice::from_raw_parts(key, 32).into());
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&pn.to_le_bytes());
    let data = core::slice::from_raw_parts_mut(buf, len);
    let tag = core::slice::from_raw_parts(buf.add(len), 16);
    match cipher.decrypt_in_place_detached(Nonce::from_slice(&nonce), b"hdr", data, tag.into()) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
