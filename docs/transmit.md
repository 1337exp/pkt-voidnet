# When the core sends a datagram (design note, stage 4b)

Status: implemented. Decision 4 of `tee/docs/architecture/online-architecture.md`.
Russian version: [transmit.ru.md](transmit.ru.md). The wire format does not change.

## The problem

Before this change `Conn::build` produced a datagram as soon as *anything* was queued, and every
second ack-eliciting packet forced an immediate ACK. A host that sent a message and called
`poll_transmit` got one datagram per message; a peer that received two datagrams answered with an
ack-only datagram. A game-like flow (50 Hz snapshots down, ~20 inputs/s up) showed about 20 ack-only
datagrams per second going up, and one extra datagram per `InputTiming` going down. There was no way
to say "these messages belong together"; the `flush` flag of the host facade did nothing.

## The model

One rule: **a datagram is built only on an explicit `flush` of the connection, or when a timer
fires.** Nothing else starts one. `send` only queues.

| Trigger | Kind | Notes |
|---|---|---|
| `flush` and something is queued | explicit | the host's way to say "now" |
| the oldest unacknowledged ack-eliciting packet has waited `max_ack_delay` | timer: acknowledgement | the only source of an ack-only datagram |
| a reliable message was declared lost and is queued again | timer: retransmit | loss is found by an ACK or by the loss timer |
| probe timeout (PTO) | timer: retransmit | PING or the oldest reliable message again |
| `queue_ping` (client confirms the connection) | PING | once, right after the handshake |
| nothing sent for `keepalive_us` | timer: keep-alive | PING |

Whatever starts a datagram, the datagram is filled the same way:

1. the **ACK frame first**, if an acknowledgement is owed (so an ACK rides on every datagram, never
   waits for its own);
2. then every queued reliable message that fits, then the queued unreliable ones.

So a message queued without `flush` *rides with the next datagram*, whatever started it. If no
trigger ever comes it waits until the keep-alive datagram at the latest; hosts that care call `flush`.
`flush` with nothing queued does nothing: in particular it never produces an ack-only datagram.
Several datagrams may be needed for one flush (a large queue); the flush stays pending until the
queue is empty, so a host that loops on `poll_transmit` drains it.

### What is removed

- "Every second ack-eliciting packet is acknowledged at once" (`eliciting_unacked >= 2`) and the
  "PING is acknowledged at once" rule. They exist in QUIC for congestion control, which we do not
  have. The state `ack_now` goes with them; what remains is `ack_owed` + `ack_since`, one rule.
- "Anything queued starts a datagram."

### State machine changes (`conn.rs`)

- New: `flush_pending: bool`, `Conn::flush()`. Invariant: it is cleared as soon as nothing is queued
  (end of `build`, end of `on_ack`), so a later `send` is not sent by a stale flush.
- Removed: `ack_now`, `eliciting_unacked`.
- `wants_to_send`: `flush_pending` ∨ ack due ∨ a retransmit is queued (a reliable message with
  `sent_once`) ∨ probe ∨ PING requested ∨ keep-alive due. A *new* reliable message or any unreliable
  one does not count.
- `next_deadline`: adds "now" while a flush or a retransmit is pending; the ack deadline is always
  `ack_since + max_ack_delay`.
- `max_ack_delay` stays an existing setting of the host (`ConnConfig`, passed by the facade). It is
  not a mode: `0` simply means the ack is due at once, which is what a host without a reverse flow
  may want.

### Choosing `max_ack_delay`

An ack-only datagram appears whenever the reverse flow leaves a gap longer than `max_ack_delay`
after something that needs an ack. With 50 Hz down and ~20 inputs/s up (a flush every 50 ms) and
`max_ack_delay` = one 20 ms tick, the client still sends about as many ack-only datagrams as before.
The delay must be longer than the longest regular gap of the reverse flow. Measurements are in the
test `standalone_acknowledgements_are_bounded_by_the_ack_delay` and the table printed by `explore_ack_only_share` of `crates/voidnet-sim/tests/gamelike.rs` and in the README.
The price of a longer delay: the sender learns about delivery and loss later by up to that much
(the PTO already includes `max_ack_delay`, so there are no false probes), and RTT samples are
corrected by the delay field of the ACK.

## Facade and C ABI

- Rust: `Conn::flush()`, `Server::flush(conn)`, `Client::flush()`.
- C: new `vn_server_flush(srv, conn)` and `vn_client_flush(cli)`; both return `VN_OK` or an error
  code (`VN_ERR_NOT_CONNECTED`, `VN_ERR_INVALID`), exactly like `send`. No existing function changes
  its signature or its struct layouts: **no ABI break**.
- **Semantics change:** `vn_*_send` no longer causes a datagram. A host that used to rely on
  `send` + `poll_transmit` must call `vn_*_flush` after the send(s) it wants on the wire now.
  Because that is a behaviour change visible to old hosts, `vn_abi_version()` goes from 1 to 2.
- `vn_*_poll_transmit` keeps its meaning: "give me the next datagram if one is due". The host calls
  it in a loop after each `flush`, after each `handle_datagram` batch, and when the deadline passes.
- The host facade maps its own `flush` flag to `vn_*_flush` on the connection it has just written to.

## What does not change

Handshake and disconnect datagrams (they are not part of `Conn`), the wire format, loss detection
(packet threshold 3, time threshold), PTO, the memory profile (`UQ_CAP`, `SENT_CAP`), channel
semantics (reliable ordered, unreliable, unreliable sequenced), the per-connection fairness of
`Server::poll_transmit`.
