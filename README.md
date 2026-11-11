# pkt-voidnet

**English** · [Русский](README.ru.md)

A small, self-contained network core for games: connections, delivery modes, resilience to hostile input. It knows nothing about the game built on top of it.

**Status: stages 1-2 done: a connection can be made, nothing is delivered yet.** The wire format is written down (`docs/wire.md`) and implemented, and so is the handshake: stateless cookie, per-source and global rate limits, a bounded connection table with generation handles, replay and forgery resistance, reconnect, timeouts. Delivery channels, RTT and keep-alive come next (stage 3).

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

Fuzz targets: `parse_datagram`, `recv_window`, `ack_frame`, `handshake_flood`. Fuzzing needs nightly and, on Windows, the ASAN runtime of Visual Studio on `PATH` (see `spike/RESULT.md`): `cargo +nightly fuzz run parse_datagram` from `fuzz/`.

## How it is built

- `docs/wire.md`: the only normative description of the bytes. `vectors/wire-v1.txt`: byte strings with their canonical reading.
- `crates/voidnet-core`: `no_std`, no allocation, `forbid(unsafe_code)`, indexing and `unwrap` denied by lint. Wire parser, packet number window, ACK frames, `Server` and `Client` state machines.
- `crates/voidnet-sim`: seeded PRNG, lossy link (loss, duplication, reordering, blackout), a small world of one server and many clients, golden trace hashes, attack and loss scenarios.
- `crates/voidnet-ffi`: the C ABI, `unsafe` lives only here.
- Design and rationale: the network core specification in the Tee repository (`docs/architecture/netcore-spec.md`).

## Not yet

- Delivery channels, acknowledgements, RTT and keep-alive (stage 3).
- The full C ABI, a build script for every OS, and bindings.

## License

MIT, see `LICENSE`.

## Us

Homepage: [666.io](https://666.io). If you want to help, suggest an idea or just talk, come by.
