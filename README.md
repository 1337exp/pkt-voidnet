# pkt-voidnet

**English** · [Русский](README.ru.md)

A small, self-contained network core for games: connections, delivery modes, resilience to hostile input. It knows nothing about the game built on top of it.

**Status: stages 1-3 done: connections work and carry data in three delivery modes, in the simulator.** The wire format, the handshake and admission, and now delivery: reliable ordered, unreliable and unreliable-sequenced channels, acknowledgements that ride on data, RTT, loss recovery, probe timers with backoff, keep-alive. Nothing is wired to a real socket or to a game yet: next is the C ABI and the Tee facade (stage 4).

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

Fuzz targets: `parse_datagram`, `recv_window`, `ack_frame`, `handshake_flood`, `conn_stream`. Fuzzing needs nightly and, on Windows, the ASAN runtime of Visual Studio on `PATH` (see `spike/RESULT.md`): `cargo +nightly fuzz run parse_datagram` from `fuzz/`.

## How it is built

- `docs/wire.md`: the only normative description of the bytes. `vectors/wire-v1.txt`: byte strings with their canonical reading.
- `crates/voidnet-core`: `no_std`, no allocation, `forbid(unsafe_code)`, indexing and `unwrap` denied by lint. Wire parser, packet number window, ACK frames, the connection (`Conn`: delivery, RTT, loss, timers), `Server` and `Client` state machines. About 100 KB per connection, fixed.
- `crates/voidnet-sim`: seeded PRNG, lossy link (loss, duplication, reordering, blackout), a small world of one server and many clients, a pair of bare connections, golden trace hashes, attack, loss and timer scenarios.
- `crates/voidnet-ffi`: the C ABI, `unsafe` lives only here.
- Design and rationale: the network core specification in the Tee repository (`docs/architecture/netcore-spec.md`).

## Not yet

- The C ABI over `Server` and `Client` (in-place initialisation in host memory), the Tee facade, a build script for every OS (stage 4).
- The full C ABI, a build script for every OS, and bindings.

## License

MIT, see `LICENSE`.

## Us

Homepage: [666.io](https://666.io). If you want to help, suggest an idea or just talk, come by.
