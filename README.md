# pkt-voidnet

**English** · [Русский](README.ru.md)

A small, self-contained network core for games: connections, delivery modes, resilience to hostile input. It knows nothing about the game built on top of it.

**Status: stage 1 done, no connections yet.** The wire format is written down (`docs/wire.md`) and implemented: datagram parser and builder, packet number window, acknowledgements, a deterministic network simulator, fuzz targets, and test vectors that a second implementation in another language checks. The handshake and delivery channels come next.

## Stack

- Core: Rust, `no_std` where possible, C ABI outward.
- First consumer: the Zig game Tee (a Zig facade over the core).
- Design goals: isolation, minimal size, testable without a network (sans-IO), layers you can opt into.

## Commands

```bash
cargo test --workspace                        # unit, property and simulator tests
cargo clippy --workspace --all-targets
zig test vectors/check.zig                    # independent Zig decoder against vectors/wire-v1.txt
UPDATE_VECTORS=1 cargo test -p voidnet-core --test vectors   # regenerate vectors after a format change
# C ABI library for Zig on Windows, then the link check:
cargo build -p voidnet-ffi --release --features abi --target x86_64-pc-windows-gnu
(cd tests/zig-abi && zig build run -Dtarget=x86_64-windows-gnu)
```

Fuzzing needs nightly and, on Windows, the ASAN runtime of Visual Studio on `PATH` (see `spike/RESULT.md`): `cargo +nightly fuzz run parse_datagram` from `fuzz/`.

## How it is built

- `docs/wire.md`: the only normative description of the bytes. `vectors/wire-v1.txt`: byte strings with their canonical reading.
- `crates/voidnet-core`: `no_std`, no allocation, `forbid(unsafe_code)`, indexing and `unwrap` denied by lint.
- `crates/voidnet-sim`: seeded PRNG, lossy link (loss, duplication, reordering, blackout), golden trace hash.
- `crates/voidnet-ffi`: the C ABI, `unsafe` lives only here.
- Design and rationale: the network core specification in the Tee repository (`docs/architecture/netcore-spec.md`).

## Not yet

- Handshake, connections, delivery channels, RTT and timeouts (stages 2 and 3).
- The full C ABI, a build script for every OS, and bindings.

## License

MIT, see `LICENSE`.

## Us

Homepage: [666.io](https://666.io). If you want to help, suggest an idea or just talk, come by.
