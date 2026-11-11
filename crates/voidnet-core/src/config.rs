//! Configuration shared by server and client, and the wire-relevant configuration hash.
//! Настройки сервера и клиента и хеш настроек, влияющих на провод.

use crate::conn::{ConnConfig, MAX_RELIABLE_CHANNELS};
use crate::siphash::siphash13;
use crate::wire::{ChannelMode, MAX_BLOB, MAX_CHANNELS, MAX_DATAGRAM};

/// The channel table: how many channels and the mode of each. Both sides must agree.
/// Таблица каналов: число и режим каждого. Стороны обязаны совпадать.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChannelTable {
    count: u8,
    modes: [ChannelMode; MAX_CHANNELS],
}

impl ChannelTable {
    /// `None` if there are more than [`MAX_CHANNELS`] modes. / `None`, если режимов больше 16.
    pub fn new(modes: &[ChannelMode]) -> Option<Self> {
        if modes.len() > MAX_CHANNELS {
            return None;
        }
        let mut t = Self {
            count: u8::try_from(modes.len()).ok()?,
            modes: [ChannelMode::Unreliable; MAX_CHANNELS],
        };
        for (d, s) in t.modes.iter_mut().zip(modes) {
            *d = *s;
        }
        Some(t)
    }

    pub fn as_slice(&self) -> &[ChannelMode] {
        self.modes.get(..usize::from(self.count)).unwrap_or(&[])
    }

    /// The hash carried in HELLO as `config_hash` (docs/wire.md, section 3): the low 32
    /// bits of SipHash-1-3 over `[count] ++ [mode...] ++ [max_datagram as u16 LE]` with the
    /// key [`CONFIG_HASH_KEY`]. Every implementation computes it the same way.
    /// Хеш из HELLO (`config_hash`): младшие 32 бита SipHash-1-3.
    pub fn config_hash(&self, max_datagram: u16) -> u32 {
        let mut msg = [0u8; 1 + MAX_CHANNELS + 2];
        let n = usize::from(self.count);
        if let Some(c) = msg.first_mut() {
            *c = self.count;
        }
        for (i, m) in self.as_slice().iter().enumerate() {
            if let Some(b) = msg.get_mut(1 + i) {
                *b = *m as u8;
            }
        }
        if let Some(d) = msg.get_mut(1 + n..3 + n) {
            d.copy_from_slice(&max_datagram.to_le_bytes());
        }
        let used = msg.get(..3 + n).unwrap_or(&[]);
        siphash13(&CONFIG_HASH_KEY, used) as u32
    }
}

/// The 16-byte key of `config_hash`: ASCII `voidnet-cfg-v1` and two zero bytes.
/// Ключ `config_hash`: ASCII `voidnet-cfg-v1` и два нулевых байта.
pub const CONFIG_HASH_KEY: [u8; 16] = *b"voidnet-cfg-v1\0\0";

/// Why a configuration cannot be used by this build. / Почему настройки не подходят этой сборке.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfigError {
    /// More reliable channels than the build keeps state for (`MAX_RELIABLE_CHANNELS`).
    TooManyReliableChannels,
    /// `max_datagram` outside what the core can build. / Недопустимый размер датаграммы.
    BadDatagramSize,
}

fn check(channels: &ChannelTable, max_datagram: u16) -> Result<(), ConfigError> {
    let reliable = channels
        .as_slice()
        .iter()
        .filter(|m| **m == ChannelMode::ReliableOrdered)
        .count();
    if reliable > MAX_RELIABLE_CHANNELS {
        return Err(ConfigError::TooManyReliableChannels);
    }
    if usize::from(max_datagram) > MAX_DATAGRAM || usize::from(max_datagram) < 64 {
        return Err(ConfigError::BadDatagramSize);
    }
    Ok(())
}

/// Application data sent to the client in ACCEPT. / Данные приложения клиенту в ACCEPT.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Blob {
    len: u8,
    bytes: [u8; MAX_BLOB],
}

impl Default for Blob {
    fn default() -> Self {
        Self {
            len: 0,
            bytes: [0; MAX_BLOB],
        }
    }
}

impl Blob {
    /// `None` if longer than [`MAX_BLOB`]. / `None`, если длиннее [`MAX_BLOB`].
    pub fn new(data: &[u8]) -> Option<Self> {
        if data.len() > MAX_BLOB {
            return None;
        }
        let mut b = Self {
            len: u8::try_from(data.len()).ok()?,
            bytes: [0; MAX_BLOB],
        };
        for (d, s) in b.bytes.iter_mut().zip(data) {
            *d = *s;
        }
        Some(b)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// Settings of a server. Every limit has an upper bound, nothing is unbounded.
/// Настройки сервера. У каждого предела есть верхняя граница.
#[derive(Clone, Copy, Debug)]
pub struct ServerConfig {
    pub protocol_id: u64,
    /// 0 accepts any client app version, otherwise it must be equal.
    pub app_version: u32,
    pub channels: ChannelTable,
    pub max_datagram: u16,
    /// At most the `N` of the server type. / Не больше `N` типа сервера.
    pub max_connections: usize,
    /// Connections from one source (address prefix) that the client has not yet confirmed with
    /// data. This is what protects the table from half-open hoarding; honest players confirm
    /// within one round trip, so a crowd behind one NAT is not affected.
    pub max_pending_per_source: usize,
    /// All connections from one source, confirmed or not. `usize::MAX` means no limit; set it
    /// that way (or high) for LAN servers and NAT-heavy audiences. Per-address policy for real
    /// players (for example "4 per IP") belongs to the host.
    pub max_per_source: usize,
    /// HELLO per source: refill per second and burst.
    pub hello_rate_per_s: u32,
    pub hello_burst: u32,
    /// HELLO from everywhere: refill per second and burst. Bounds the work and the
    /// outgoing traffic when the sources are spoofed.
    pub global_rate_per_s: u32,
    pub global_burst: u32,
    /// A cookie is valid when its time is within this many seconds of the server clock.
    pub cookie_freshness_s: u32,
    /// How often the host is asked to rotate the secrets (see `Server::next_deadline`).
    pub rotation_interval_us: u64,
    /// A connection the client never confirmed with data is dropped after this.
    pub unconfirmed_timeout_us: u64,
    /// A connection with no valid datagram for this long is closed.
    pub idle_timeout_us: u64,
    /// How long an acknowledgement may wait for a data datagram to ride on. One simulation
    /// tick is a good value for a game.
    pub max_ack_delay_us: u64,
    /// Send a PING after this long without sending anything. 0 disables keep-alive.
    pub keepalive_us: u64,
    /// RTT assumed before the first measurement.
    pub initial_rtt_us: u64,
    pub accept_blob: Blob,
}

impl ServerConfig {
    pub fn new(protocol_id: u64, channels: ChannelTable) -> Self {
        Self {
            protocol_id,
            app_version: 0,
            channels,
            max_datagram: MAX_DATAGRAM as u16,
            max_connections: usize::MAX,
            max_pending_per_source: 4,
            max_per_source: 16,
            hello_rate_per_s: 20,
            hello_burst: 10,
            global_rate_per_s: 5_000,
            global_burst: 500,
            cookie_freshness_s: 5,
            rotation_interval_us: 240_000_000,
            unconfirmed_timeout_us: 5_000_000,
            idle_timeout_us: 30_000_000,
            max_ack_delay_us: 25_000,
            keepalive_us: 1_000_000,
            initial_rtt_us: 100_000,
            accept_blob: Blob::default(),
        }
    }

    pub fn config_hash(&self) -> u32 {
        self.channels.config_hash(self.max_datagram)
    }

    /// Settings of every connection this server holds. / Настройки каждого соединения сервера.
    pub fn conn_config(&self) -> ConnConfig {
        ConnConfig {
            channels: self.channels,
            max_ack_delay_us: self.max_ack_delay_us,
            keepalive_us: self.keepalive_us,
            initial_rtt_us: self.initial_rtt_us,
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        check(&self.channels, self.max_datagram)
    }
}

/// Settings of a client. / Настройки клиента.
#[derive(Clone, Copy, Debug)]
pub struct ClientConfig {
    pub protocol_id: u64,
    pub app_version: u32,
    pub channels: ChannelTable,
    pub max_datagram: u16,
    /// Resend HELLO or RESPONSE after this long without an answer.
    pub retry_interval_us: u64,
    /// RESPONSE resends before the client falls back to a new HELLO.
    pub response_retries: u8,
    /// Give up on the handshake after this long.
    pub handshake_timeout_us: u64,
    pub idle_timeout_us: u64,
    pub max_ack_delay_us: u64,
    pub keepalive_us: u64,
    pub initial_rtt_us: u64,
}

impl ClientConfig {
    pub fn new(protocol_id: u64, channels: ChannelTable) -> Self {
        Self {
            protocol_id,
            app_version: 0,
            channels,
            max_datagram: MAX_DATAGRAM as u16,
            retry_interval_us: 500_000,
            response_retries: 4,
            handshake_timeout_us: 10_000_000,
            idle_timeout_us: 30_000_000,
            max_ack_delay_us: 25_000,
            keepalive_us: 1_000_000,
            initial_rtt_us: 100_000,
        }
    }

    pub fn config_hash(&self) -> u32 {
        self.channels.config_hash(self.max_datagram)
    }

    pub fn conn_config(&self) -> ConnConfig {
        ConnConfig {
            channels: self.channels,
            max_ack_delay_us: self.max_ack_delay_us,
            keepalive_us: self.keepalive_us,
            initial_rtt_us: self.initial_rtt_us,
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        check(&self.channels, self.max_datagram)
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn config_hash_depends_on_every_input() {
        let a =
            ChannelTable::new(&[ChannelMode::ReliableOrdered, ChannelMode::Unreliable]).unwrap();
        let b =
            ChannelTable::new(&[ChannelMode::Unreliable, ChannelMode::ReliableOrdered]).unwrap();
        let c = ChannelTable::new(&[ChannelMode::ReliableOrdered]).unwrap();
        let h = a.config_hash(1400);
        assert_ne!(h, b.config_hash(1400));
        assert_ne!(h, c.config_hash(1400));
        assert_ne!(h, a.config_hash(1200));
        assert_eq!(h, a.config_hash(1400));
    }

    #[test]
    fn too_many_channels_and_blobs_are_refused() {
        assert!(ChannelTable::new(&[ChannelMode::Unreliable; 17]).is_none());
        assert!(ChannelTable::new(&[ChannelMode::Unreliable; 16]).is_some());
        assert!(Blob::new(&[0; 33]).is_none());
        assert_eq!(Blob::new(b"ab").unwrap().as_bytes(), b"ab");
    }
}
