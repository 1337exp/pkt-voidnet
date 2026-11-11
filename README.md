# pkt-voidnet

**English** · [Русский](README.ru.md)

A small, self-contained network core for games: connections, delivery modes, resilience to hostile input. It knows nothing about the game built on top of it.

**Status: design stage.** Nothing here is a library yet. The first step is checking that a Rust core can be linked into a Zig game on Windows (see `spike/abi-probe/RESULT.md`: it works with the gnu target).

## Stack

- Core: Rust, `no_std` where possible, C ABI outward.
- First consumer: the Zig game Tee (a Zig facade over the core).
- Design goals: isolation, minimal size, testable without a network (sans-IO), layers you can opt into.

## Not yet

- The core itself, a build script for every OS, and bindings.
- A written specification (a design session is planned).

## License

MIT, see `LICENSE`.

## Us

Homepage: [666.io](https://666.io). If you want to help, suggest an idea or just talk, come by.
