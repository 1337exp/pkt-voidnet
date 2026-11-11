//! pkt-voidnet core, stage 1: wire format, packet number window, acknowledgements.
//!
//! Sans-IO, `no_std`, no allocation, no `unsafe`. The normative description of every
//! byte is `docs/wire.md`; this crate must match it.
//!
//! Ядро pkt-voidnet, этап 1: формат на проводе, окно номеров пакетов, подтверждения.
//! Без ввода-вывода, `no_std`, без выделения памяти, без `unsafe`. Нормативное
//! описание каждого байта лежит в `docs/wire.md`; крейт обязан ему соответствовать.

#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

#[cfg(test)]
extern crate std;

pub mod ack;
pub mod dump;
pub mod io;
pub mod varint;
pub mod window;
pub mod wire;

pub use ack::AckFrame;
pub use wire::{
    ChannelMode, DataDatagram, DataWriter, Datagram, Frame, HelloFields, ParseError, WriteError,
};

/// ABI/protocol generation of this build, `(major << 16) | minor`.
/// Поколение ABI/протокола этой сборки, `(major << 16) | minor`.
pub const ABI_VERSION: u32 = 1;
