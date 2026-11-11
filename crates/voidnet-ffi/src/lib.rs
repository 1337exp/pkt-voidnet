//! C ABI of pkt-voidnet. Stage 1 exports only the version; the rest arrives with the
//! connection state machines. `unsafe` is allowed in this crate only.
//! C ABI pkt-voidnet. Этап 1 отдаёт только версию; остальное придёт с автоматами соединений.

// The release library is built with `--features abi`: `no_std`, `panic = "abort"`.
// Without the feature the crate is an ordinary std library, so `cargo test` works.
// Релизная библиотека собирается с `--features abi`: `no_std`, `panic = "abort"`.
#![cfg_attr(feature = "abi", no_std)]

/// `(major << 16) | minor` of the ABI. / Версия ABI.
#[no_mangle]
pub extern "C" fn vn_abi_version() -> u32 {
    voidnet_core::ABI_VERSION
}

/// Wire format generation (`wire_version` in HELLO). / Поколение формата на проводе.
#[no_mangle]
pub extern "C" fn vn_wire_version() -> u32 {
    u32::from(voidnet_core::wire::WIRE_VERSION)
}

#[cfg(feature = "abi")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Panics are defects (invariant I4); the build uses panic = "abort".
    loop {}
}

#[cfg(feature = "abi")]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_nonzero() {
        assert_eq!(super::vn_abi_version(), voidnet_core::ABI_VERSION);
        assert_eq!(super::vn_wire_version(), 1);
    }
}
