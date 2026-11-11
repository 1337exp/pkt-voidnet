# ABI probe: Rust staticlib linked by Zig on Windows (2026-11-11)

Question: can a Rust core be linked into the Zig game, whose `build.bat` targets portable `x86_64-windows-gnu` (MinGW, no VC++ redist)?

Setup: Rust 1.99.1, Zig 0.17.0, `no_std` staticlib with one `extern "C"` function, `panic = "abort"`. The Zig exe calls it and returns the result as its exit code (2 + 3 must give 5).

| Rust target | Zig target | Result |
|---|---|---|
| `x86_64-pc-windows-gnu` | `x86_64-windows-gnu` | **works**, exit code 5 |
| `x86_64-pc-windows-msvc` | `x86_64-windows-gnu` | **fails**: `lld-link: duplicate symbol: .weak.__divti3.default` (Rust `compiler_builtins` and Zig `compiler_rt` both define it) |

Notes:

- Building the gnu staticlib needs only `rustup target add x86_64-pc-windows-gnu`; no MinGW toolchain on the machine, because a staticlib is not linked by Rust.
- A `no_std` staticlib needs an empty `rust_eh_personality` stub (see `src/lib.rs`), otherwise the link fails with `undefined symbol: rust_eh_personality`.
- Not covered by this probe: a core with `alloc`, threads or sockets; Linux and macOS; Zig `build.zig` integration (this probe used `zig build-exe` directly).

Reproduce:

```bash
cd spike/abi-probe
cargo build --release --target x86_64-pc-windows-gnu
zig build-exe probe.zig target/x86_64-pc-windows-gnu/release/libvoidnet_probe.a -target x86_64-windows-gnu --name probe_gnu
./probe_gnu.exe; echo $?   # 5
```
