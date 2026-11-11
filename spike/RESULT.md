# Spike results S1-S5, S7 (2026-11-11)

Environment: Windows 11, Rust 1.99.1 stable (+ nightly 1.102 for cargo-fuzz), Zig 0.17.0. Spec: `tee/docs/architecture/netcore-spec.md`, section 5.5. Earlier probe: `abi-probe/RESULT.md`.

| # | Question | Result | Where |
|---|---|---|---|
| S1 | Link through `build.zig`, not `zig build-exe` | **works.** `mod.addObjectFile(b.path(lib))` on the root module, `zig build run -Dtarget=x86_64-windows-gnu` exits 0 | `host-probe/build.zig` |
| S2 | State placed in host-owned memory, no `alloc` | **works.** Rust `vn_server_size/align/init` place a 66 KiB struct into a buffer allocated by Zig; null, misaligned and too-small are rejected with distinct codes; Zig must align the buffer by hand because `alignedAlloc` takes a comptime alignment | `host-probe/` |
| S3 | `u128` mul/div/rem, variable `memcpy`/`memset` against Zig compiler-rt | **works** under gnu: a digest computed in Rust equals the one computed in Zig for six lengths | `host-probe/` |
| S4 | Linux and macOS | **links, not executed.** `rustup target add` for linux-gnu, linux-musl, aarch64-linux, aarch64-macos, x86_64-macos; Rust staticlib built on Windows without any C toolchain or SDK; Zig linked all five (ELF verified with `file`). Running needs those OSes, so CI is still to do | `host-probe/` |
| S5 | Crypto for the optional AEAD layer in `no_std` | **works.** `siphasher` (SipHash-1-3) and `chacha20poly1305` (`heapless`) in a `no_std` staticlib match Zig `std.crypto` byte for byte, tampered data fails to open. Linked exe 76 KB (ReleaseSmall) | `crypto-probe/` |
| S6 | Size | `.a` is 3 MB (carries `core`), linked exe 52 KB (host-probe, ReleaseSmall) and 76 KB (crypto-probe) | above |
| S7 | cargo-fuzz on this machine | **works with a workaround.** `cargo install cargo-fuzz` OK, needs the nightly toolchain. Default run fails with `STATUS_DLL_NOT_FOUND`: the ASAN runtime is not on PATH. Put `...\VC\Tools\MSVC\<ver>\bin\Hostx64\x64` on PATH and it runs. `--sanitizer none` does not link on msvc (`__start___sancov_cntrs`). A planted out-of-bounds bug was found in under a second | `fuzz-probe/` |

Zig target is 0.17 only (author decision); 0.16 is not checked.

Not done: S8 (`cargo-zigbuild`, judged not needed for staticlib), S9 (`cdylib`, WASM), running the Linux and macOS binaries.

Reproduce:

```bash
cd spike/host-probe
cargo build --release --target x86_64-pc-windows-gnu
zig build run -Dtarget=x86_64-windows-gnu            # exit 0 = ok
cargo build --release --target x86_64-unknown-linux-gnu
zig build install -Dtarget=x86_64-linux-gnu -Dvoidnet-lib=target/x86_64-unknown-linux-gnu/release/libvoidnet_host_probe.a
```
