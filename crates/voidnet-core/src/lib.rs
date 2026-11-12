//! pkt-voidnet core, stages 1-2: wire format, packet number window, acknowledgements,
//! handshake and admission (server and client state machines).
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
pub mod addr;
pub mod client;
pub mod config;
pub mod conn;
pub mod dump;
pub mod io;
pub mod limit;
pub mod ring;
pub mod server;
pub mod siphash;
pub mod varint;
pub mod window;
pub mod wire;

pub use ack::AckFrame;
pub use addr::Addr;
pub use client::{Client, ClientEvent, Failed};
pub use config::{Blob, ChannelTable, ClientConfig, ConfigError, ServerConfig};
pub use conn::{Conn, ConnConfig, ConnStats, SendError};
pub use server::{Closed, ConnId, Event, Received, Server};
pub use wire::{
    ChannelMode, DataDatagram, DataWriter, Datagram, Frame, HelloFields, ParseError, WriteError,
};

/// ABI/protocol generation of this build, `(major << 16) | minor`.
/// Поколение ABI/протокола этой сборки, `(major << 16) | minor`.
pub const ABI_VERSION: u32 = 2;
