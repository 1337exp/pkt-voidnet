# pkt-voidnet wire format, version 1 (draft 0.1)

**English** · [Русский](wire.ru.md)

This file is the single source of truth for the bytes on the wire. Anyone can implement a client, a bot or a tool from this page and the vectors in `vectors/wire-v1.txt`; there is no other normative source. Where the Rust code and this file disagree, the file wins and the code is a bug.

Status: **draft**. Layouts in sections 1-4 and `config_hash` (section 5) are fixed and covered by vectors. The handshake rules in section 6 are implemented and tested on the simulator (stage 2).

## 0. Conventions

- All fixed-width integers are **little-endian**. `u8`, `u16`, `u32`, `u64` are unsigned.
- `varint` is unsigned LEB128 limited to `u32`: 1-5 bytes, 7 value bits per byte, the high bit means "more". **Canonical form only**: a multi-byte varint whose last byte is `0x00` is invalid, and so is any value above `u32::MAX`.
- A datagram is at most **1400 bytes** (`MAX_DATAGRAM`). A longer input is dropped.
- **Strict parsing.** Any violation of this file (reserved value, wrong length, non-zero padding, unknown tag, non-canonical varint, frame order) makes the receiver **drop the whole datagram silently**. No error reply is ever sent for a datagram that fails to parse.
- Every layout has exactly one valid encoding. Parsing a valid datagram and encoding the result gives back the same bytes (the fuzz target checks this).

## 1. Datagram kinds

The first byte is the kind. Anything not listed is invalid.

| Byte | Kind | Direction | Length |
|---|---|---|---|
| `0x00` | DATA | both | 12-1400 |
| `0x80` | HELLO | client to server | exactly 64 |
| `0x81` | CHALLENGE | server to client | exactly 13 |
| `0x82` | RESPONSE | client to server | exactly 64 |
| `0x83` | ACCEPT | server to client | 22 + `blob_len` |
| `0x84` | REJECT | server to client | exactly 10 |
| `0x01` | reserved: sealed DATA (optional encryption layer) | | invalid in v1 |

Design rule: **a reply to an unverified address is never longer than the datagram that caused it.** HELLO (64 bytes) can only trigger CHALLENGE (13) or REJECT (10); RESPONSE (64) can only trigger ACCEPT (at most 54) or REJECT (10).

## 2. DATA

```
00 | token:u64 | pn:u16 | frame...
```

- `token`: the session token issued in ACCEPT, the same in both directions of one connection. Compared in constant time.
- `pn`: the low 16 bits of the sender's **packet number**. Packet numbers are 64-bit, start at 0 for each direction, increase by 1 for every DATA datagram sent and are **never reused: a retransmission gets a new number**. The receiver reconstructs the full value (section 2.1).
- At least one frame is required. Frames fill the rest of the datagram exactly.

### 2.1 Packet number reconstruction

Let `expected` be the largest full packet number received so far plus 1 (0 if none). The full number is the unique value congruent to `pn` modulo 2^16 in the interval `(expected - 2^15, expected + 2^15]`. If that value would be negative, the datagram is dropped. This is correct while the true number lies in that interval; a sender must never let its packet numbers run 2^15 or more ahead of the largest the peer has received.

### 2.2 Receive window

Receivers keep a window of the **256** most recent packet numbers. A number inside the window that was already received is a **duplicate**, a number below the window is **too old**; both are dropped before any other processing. This is what guarantees a datagram is never delivered twice.

### 2.3 Frames

A frame starts with a one-byte **tag**.

| Tag | Frame |
|---|---|
| `0x00`-`0x0F` | MSG: application message on channel `tag` |
| `0x10` | ACK |
| `0x11` | PING |
| `0x12` | DISCONNECT |
| `0x13`-`0x1F` | reserved (fragment, receipt, credit); invalid in v1 |
| `0x20`-`0xFF` | invalid |

Order rules: **ACK, if present, is the first frame; DISCONNECT, if present, is the last; ACK, PING and DISCONNECT appear at most once.** A datagram holding only an ACK frame is *ack-only*; every other datagram is *ack-eliciting* and obliges the receiver to acknowledge it.

#### MSG

```
tag(= channel) | [mseq:u16] | len:varint | payload[len]
```

`mseq` is present only if the channel is *numbered* (modes `unreliable_sequenced` and `reliable_ordered`). `len` may be 0. A tag at or above the number of configured channels is invalid. The channel table (count and mode of each channel, at most 16) is configuration known to both sides; its hash is checked in the handshake (section 3).

| Mode | Value | Numbered | Guarantee |
|---|---|---|---|
| `unreliable` | 0 | no | at most once, any order |
| `unreliable_sequenced` | 1 | yes | at most once, only newer than the newest seen |
| `reliable_ordered` | 2 | yes | exactly once, in order, while the connection lives |

`mseq` is a per-channel, per-direction counter that wraps at 2^16 and is compared as a serial number (distance below 2^15).

#### ACK

```
10 | largest:u16 | delay:varint | n:u8 | first:varint | (gap:varint | len:varint) x n
```

- `largest`: low 16 bits of the largest packet number acknowledged. The receiver of the frame reconstructs it as the largest value, not above the highest packet number it has sent, that has these low bits.
- `delay`: how long the sender of the frame held packet `largest` before acknowledging it, in units of **32 microseconds**. Used to correct RTT samples.
- The first block acknowledges `first` packets ending at `largest`. Each of the `n` following blocks is `gap` unacknowledged packet numbers below the previous block, then `len` acknowledged ones.
- Constraints: `n <= 15`, `first >= 1`, `gap >= 1`, `len >= 1`, total span `first + sum(gap + len) <= 32768`, and no block may reach below packet number 0.

There is no ack-only datagram unless an acknowledgement has been owed for longer than the configured maximum ack delay.

#### PING

```
11
```

Keep-alive and RTT probe. It is ack-eliciting; the acknowledgement is the reply (there is no PONG).

#### DISCONNECT

```
12 | reason:u8
```

Graceful close with a one-byte reason code. The meaning of a code belongs to the application; the core defines only `0` = normal. Senders send it in three datagrams.

## 3. Handshake datagrams

Handshake datagrams are cleartext. Unused bytes are padding and **must be zero**.

`HELLO FIELDS` (29 bytes), used in HELLO and RESPONSE:

```
wire_version:u8 | protocol_id:u64 | app_version:u32 | config_hash:u32 | client_random:u64 | caps:u32
```

| Field | Meaning |
|---|---|
| `wire_version` | `1` for this document. For any other value the remaining fields are undefined and the server answers REJECT. |
| `protocol_id` | the application's wire gate; a mismatch is rejected |
| `app_version` | application version; the application decides compatibility |
| `config_hash` | hash of the wire-relevant configuration, defined in section 5; a mismatch is rejected |
| `client_random` | 8 fresh random bytes per connection attempt |
| `caps` | capability bits; none are defined in v1, send 0, ignore unknown bits |

```
HELLO      80 | HELLO FIELDS | zero padding to 64 bytes
CHALLENGE  81 | coarse:u32 | cookie:u64                                  (13 bytes)
RESPONSE   82 | coarse:u32 | cookie:u64 | HELLO FIELDS | zero padding to 64 bytes
ACCEPT     83 | token:u64 | echo:u64 | caps:u32 | blob_len:u8 | blob[blob_len]
REJECT     84 | code:u8 | echo:u64                                       (10 bytes)
```

- `coarse`: the server clock in whole seconds when the cookie was made.
- `cookie`: a 64-bit address-bound tag (section 5). The client echoes `coarse` and `cookie` in RESPONSE together with the same HELLO FIELDS, so the server keeps no state between HELLO and RESPONSE.
- `echo`: the client's `client_random`. A client accepts ACCEPT or REJECT only if `echo` matches the value it sent; this stops an off-path attacker from forging them.
- `token`: the session token (section 5).
- `blob`: up to 32 bytes of application data from server to client (for example game parameters); `blob_len <= 32`.
- `code` in REJECT: `1` version (wire version, protocol id or app version), `2` config mismatch, `3` server full, `4` rate limited, `5` too many connections from this source (a limit on *unconfirmed* connections from one source is not answered with a REJECT: the client keeps retrying and gets in when there is room). Other values are application-defined.

## 4. Sizes

| Item | Bytes |
|---|---|
| DATA header | 11 |
| MSG overhead, numbered channel, payload under 128 bytes | 1 + 2 + 1 = 4 |
| MSG overhead, unnumbered channel, payload under 128 bytes | 1 + 1 = 2 |
| ACK frame, one block, short delay | about 7 |

The shortest DATA datagram is 12 bytes (a PING).

## 5. Derived values

**`config_hash`** is the only derived value two implementations must compute identically. It is the low 32 bits of SipHash-1-3 (64-bit output) with the key `"voidnet-cfg-v1"` followed by two zero bytes, over:

```
count:u8 | mode:u8 x count | max_datagram:u16
```

where `mode` is the numeric value from the channel mode table in section 2.3 and `max_datagram` is the configured datagram size, little-endian. `vectors/config-hash-v1.txt` lists cases.

**Cookie and token are private to the server.** The client never computes or checks them, so they are not part of the wire format. An implementation must only guarantee these properties:

- A cookie is a 64-bit tag that can be verified without stored state and depends on the source address (all address bytes including the port), `coarse`, and every field of HELLO FIELDS, under a secret the server rotates. A previous secret is also accepted for one period. A cookie is valid if `coarse` is within 5 seconds of the server clock (configurable).
- A token is 64 bits, unpredictable to anyone without the server's key, and different for every connection.
- Comparisons of cookies and tokens take constant time.

The reference implementation uses SipHash-1-3 for both (`crates/voidnet-core/src/server.rs`).

## 6. Handshake flow and rules

```
client                         server
  HELLO  ------------------->            no state stored
         <------------------  CHALLENGE   (or REJECT)
  RESPONSE ------------------>            verifies the cookie, takes a slot (pending)
         <------------------  ACCEPT      (or REJECT)
  DATA (ping) --------------->            first authentic DATA: connection confirmed
         <------------------  DATA (ping)
  DATA ...  <------------->  DATA ...
```

- **No server state before a valid cookie.** A RESPONSE takes a slot, but the host is told about the connection only when the client's first authentic DATA arrives (confirmed). A pending connection that is never confirmed is dropped silently after a timeout (default 5 s). This keeps clients that never completed the handshake invisible to the application and short-lived in the table.
- **Confirmation.** After ACCEPT the client sends a PING in a DATA datagram. The server acknowledges it at once (a PING is acknowledged without delay), and that acknowledgement is the first authentic DATA the client sees, which confirms the path both ways. If the PING is lost the probe timeout sends another.
- **Limits at the server.** Per-source token bucket for HELLO, then a global bucket for HELLO (the per-source one goes first so one address cannot drain the global one), a cap on connections per source, a cap on all connections. A refused request gets REJECT only when that is cheap and safe (version, config, full, source limit); rate-limited requests get no reply.
- **Same address connects again:** a valid RESPONSE with the same `client_random` repeats ACCEPT with the same token (idempotent, covers a lost ACCEPT); with a different `client_random` the old connection is closed (the host sees it as replaced) and a new one is created.
- **Client retries.** HELLO or RESPONSE is resent every retry interval (default 500 ms). After a few RESPONSE resends without an answer (default 4) the client starts over with a new HELLO, which recovers from a forged or stale CHALLENGE. The whole attempt times out after the handshake timeout (default 10 s).
- **Idle timeout** (default 30 s of no authentic datagram) ends a connection on either side; keep-alive (section 7) keeps an idle connection open.
- Timeouts, intervals and limits are host configuration, not wire values.

## 7. Delivery and liveness rules (behaviour, not layout)

The layouts above are enough to parse; these rules are what makes two implementations behave
alike. Values in brackets are defaults of the reference implementation.

**Acknowledgements.**
- A datagram with any frame other than ACK is *ack-eliciting*. Receiving one makes an acknowledgement *owed*.
- An owed acknowledgement is sent in the next datagram of any kind (it rides along, there is no extra datagram), or on its own when it has waited `max_ack_delay` [25 ms], or at once when the datagram contained a PING or when two ack-eliciting datagrams are waiting.
- `delay` in the ACK frame is the time since the largest acknowledged packet arrived, in units of 32 microseconds.
- A datagram that is refused (wrong token, duplicate, too old, or a message the receiver cannot keep) is **not** acknowledged.

**RTT.** When an ACK frame newly acknowledges its own `largest` and that packet was ack-eliciting, the sample is `now - time_sent - min(delay, max_ack_delay)`. `srtt = 7/8 srtt + 1/8 sample`, `rttvar = 3/4 rttvar + 1/4 |srtt - sample|`; the first sample sets `srtt = sample`, `rttvar = sample / 2`. Before a sample the RTT is assumed [100 ms].

**Loss.** A packet is lost when an acknowledgement covers a packet at least 3 numbers above it, or when it is older than `9/8 * max(srtt, latest sample)` and an acknowledgement covers a later packet. The reliable messages it carried are queued again, under a new packet number.

**Probe timeout.** `pto = srtt + max(4 * rttvar, 1 ms) + max_ack_delay`. If the newest ack-eliciting packet has been unacknowledged for `pto * 2^k` (k counts timeouts since the last acknowledgement, at most 6), the sender sends two probes: the oldest unacknowledged reliable message again, or a PING if there is none. An acknowledgement resets `k`. There is no congestion window; a dead path costs one probe per backed-off interval and a keep-alive.

**Keep-alive and idle.** After `keepalive` [1 s] without sending any datagram, a PING is sent. A connection with no authentic datagram for the idle timeout [30 s] is closed on that side. A sender never lets its packet numbers run 2^14 ahead of the largest one the peer acknowledged.

**Modes.**
- `reliable_ordered`: at most 16 messages in flight per channel (the *window*). A message that does not fit the window is refused whole (`Full`), never half queued. The receiver keeps messages that arrive early, delivers in order, and refuses (without acknowledging) a datagram holding a reliable message 16 or more ahead of the next one it expects. Messages already delivered are ignored when they arrive again.
- `unreliable_sequenced`: delivered only if newer than the newest delivered so far.
- `unreliable`: delivered as it arrives. Up to 8 messages wait to be sent; a new one replaces the oldest when the queue is full, so an unreliable message never waits behind anything.
- A message is at most 1200 bytes. The receiver holds at most 8 messages for the host; when the host does not read, reliable messages wait in the window (backpressure), unreliable ones are dropped.

**Build-time profile.** The window (16), the number of reliable channels (2), the queue sizes, the history of 64 tracked packets and the message size (1200) are constants of the library build, so the memory of a connection is known in advance (about 100 KiB). A different profile is a different build and does not change the wire format.

## 8. Versioning

`wire_version` (one byte in HELLO) identifies this document's layouts. Frame tags `0x13`-`0x1F`, the kind `0x01` and the `caps` bits are reserved for extensions. A change to any layout in this file requires a new `wire_version`.

## 9. Vectors

`vectors/wire-v1.txt` lists byte strings and the canonical description of how each must be read. See the header of that file for the line format and the channel table the vectors assume. An implementation conforms when it produces exactly the listed description for every line and drops exactly the lines marked `drop`.
