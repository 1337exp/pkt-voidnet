/*
 * pkt-voidnet C ABI.
 *
 * The rules of the boundary:
 *  - The host owns all memory. Ask vn_server_size() / vn_server_align() (and the client
 *    equivalents), allocate that much, hand the block to vn_*_init(). The library never
 *    allocates and never frees. The block must stay where it is while in use.
 *  - No pointer passed to a call is kept after it returns.
 *  - No callbacks, no threads, no clock, no randomness: time (microseconds, monotonic) and
 *    entropy come in as arguments.
 *  - One object is used by one thread at a time; separate objects are independent.
 *  - Functions return 0 or a count on success and a negative VN_ERR_* code on failure.
 *  - Structs the host fills begin with struct_size and only ever grow at the end.
 *
 * Everything normative about the bytes on the wire is in docs/wire.md.
 *
 * Хозяин владеет всей памятью; ни один указатель не хранится после возврата; нет колбэков,
 * потоков, часов и случайности; функции возвращают числа; структуры начинаются с struct_size.
 */
#ifndef VOIDNET_H
#define VOIDNET_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- codes ---------------------------------------------------------------------------- */

#define VN_OK 0
#define VN_ERR_INVALID (-1)
#define VN_ERR_FULL (-2)          /* reliable window full: nothing was queued */
#define VN_ERR_TOO_BIG (-3)
#define VN_ERR_NO_CHANNEL (-4)
#define VN_ERR_NOT_CONNECTED (-5) /* also: stale connection handle */
#define VN_ERR_NO_MEM (-6)        /* the block is smaller than vn_*_size() */
#define VN_ERR_ALIGN (-7)
#define VN_ERR_CONFIG (-8)
#define VN_ERR_VERSION (-9)

#define VN_EVENT_CONNECTED 1u
#define VN_EVENT_DISCONNECTED 2u
#define VN_EVENT_FAILED 3u /* client only: the connection attempt failed */

#define VN_REASON_NONE 0
#define VN_REASON_LOCAL 1    /* we closed it; reason_code is ours */
#define VN_REASON_REMOTE 2   /* the peer closed it; reason_code is the peer's */
#define VN_REASON_TIMEOUT 3
#define VN_REASON_REPLACED 4 /* the same address connected again */
#define VN_REASON_REJECTED 5 /* client: the server said no; reason_code is the REJECT code */
#define VN_REASON_NO_ANSWER 6

/* REJECT codes (docs/wire.md): 1 version, 2 config, 3 server full, 4 rate limited, 5 source limit */

#define VN_MODE_UNRELIABLE 0
#define VN_MODE_UNRELIABLE_SEQUENCED 1
#define VN_MODE_RELIABLE_ORDERED 2

/* ---- plain structs -------------------------------------------------------------------- */

typedef struct vn_addr {
    uint8_t len;        /* 1..20 */
    uint8_t source_len; /* first source_len bytes name the source for rate limits (the IP) */
    uint8_t bytes[20];  /* recommended: 16 bytes IPv6 or IPv4-mapped, then 2 bytes port */
} vn_addr;

typedef struct vn_conn {
    uint32_t index;
    uint32_t generation; /* changes when the slot is reused: a stale handle never works */
} vn_conn;

typedef struct vn_event {
    uint32_t kind;
    vn_conn conn;
    vn_addr addr; /* for VN_EVENT_CONNECTED */
    uint8_t reason_kind;
    uint8_t reason_code;
} vn_event;

typedef struct vn_recv {
    vn_conn conn;
    uint8_t ch;
    uint8_t reserved[3];
    uint32_t len;
} vn_recv;

typedef struct vn_client_event {
    uint32_t kind;
    uint8_t reason_kind;
    uint8_t reason_code;
    uint8_t blob_len; /* application data the server put in ACCEPT */
    uint8_t reserved;
    uint32_t caps;
    uint8_t blob[32];
} vn_client_event;

typedef struct vn_conn_stats {
    uint64_t packets_sent, packets_recv, bytes_sent, bytes_recv, ack_only_sent;
    uint64_t packets_lost, messages_resent, duplicates_dropped, refused_capacity, probes;
    uint64_t rtt_us, rtt_var_us, min_rtt_us, latest_rtt_us;
} vn_conn_stats;

typedef struct vn_server_stats {
    uint64_t datagrams, bytes_in, bytes_out, parse_errors, hello, response;
    uint64_t rate_limited_source, rate_limited_global, bad_cookie, stale_cookie, challenges;
    uint64_t accepted, rejected_full, deferred_pending, confirmed, bad_token, unknown_peer;
} vn_server_stats;

/* Fill with vn_server_config_default(), then change what you need. */
typedef struct vn_server_config {
    uint32_t struct_size;
    uint32_t app_version; /* 0 accepts any client version */
    uint64_t protocol_id;
    uint64_t rotation_interval_us;
    uint64_t unconfirmed_timeout_us;
    uint64_t idle_timeout_us;
    uint64_t max_ack_delay_us;
    uint64_t keepalive_us;
    uint64_t initial_rtt_us;
    uint32_t max_connections;        /* 0: all slots of the build */
    uint32_t max_per_source;         /* 0xFFFFFFFF: no limit (LAN, NAT) */
    uint32_t max_pending_per_source; /* unconfirmed connections from one source */
    uint32_t hello_rate_per_s;
    uint32_t hello_burst;
    uint32_t global_rate_per_s;
    uint32_t global_burst;
    uint32_t cookie_freshness_s;
    uint16_t max_datagram;
    uint8_t channel_count; /* both sides must use the same table */
    uint8_t blob_len;
    uint8_t channel_modes[16]; /* VN_MODE_* */
    uint8_t blob[32];
} vn_server_config;

typedef struct vn_client_config {
    uint32_t struct_size;
    uint32_t app_version;
    uint64_t protocol_id;
    uint64_t retry_interval_us;
    uint64_t handshake_timeout_us;
    uint64_t idle_timeout_us;
    uint64_t max_ack_delay_us;
    uint64_t keepalive_us;
    uint64_t initial_rtt_us;
    uint16_t max_datagram;
    uint8_t channel_count;
    uint8_t response_retries;
    uint8_t channel_modes[16];
} vn_client_config;

/* Sizes and limits of this build, so a binding can check its own struct definitions. */
typedef struct vn_abi_info {
    uint32_t abi_version, wire_version;
    uint32_t sizeof_addr, sizeof_conn, sizeof_event, sizeof_recv, sizeof_client_event;
    uint32_t sizeof_conn_stats, sizeof_server_stats, sizeof_server_config, sizeof_client_config;
    uint32_t msg_max, max_datagram, server_slots, max_channels;
} vn_abi_info;

typedef struct vn_server vn_server; /* lives in host memory, opaque */
typedef struct vn_client vn_client;

/* ---- general -------------------------------------------------------------------------- */

uint32_t vn_abi_version(void); /* (major << 16) | minor */
uint32_t vn_wire_version(void);
int32_t vn_abi_info(vn_abi_info* out);

/* ---- server --------------------------------------------------------------------------- */

int32_t vn_server_config_default(vn_server_config* cfg, uint64_t protocol_id);
size_t vn_server_size(void);
size_t vn_server_align(void);
/* seed: 32 fresh random bytes from the OS. */
int32_t vn_server_init(void* mem, size_t len, const vn_server_config* cfg, const uint8_t* seed,
                       uint64_t now_us);
/* Call on a timer (see vn_server_next_deadline) with 16 fresh random bytes. */
void vn_server_rotate_secret(vn_server* s, const uint8_t* fresh16, uint64_t now_us);

void vn_server_handle_datagram(vn_server* s, const vn_addr* from, const uint8_t* data, size_t len,
                               uint64_t now_us);
/* Run the timers: every loop iteration, or when vn_server_next_deadline has passed. */
void vn_server_handle_timeout(vn_server* s, uint64_t now_us);
uint64_t vn_server_next_deadline(const vn_server* s); /* UINT64_MAX: never */
/* Returns the datagram length (0: nothing to send); the destination goes to *to. cap >= 1400. */
size_t vn_server_poll_transmit(vn_server* s, uint8_t* buf, size_t cap, vn_addr* to, uint64_t now_us);
/* 1: event written, 0: none. */
int32_t vn_server_poll_event(vn_server* s, vn_event* out);
int32_t vn_server_send(vn_server* s, vn_conn conn, uint8_t ch, const uint8_t* data, size_t len);
/* 1: message received (bytes in buf, details in *out), 0: none. cap >= msg_max. */
int32_t vn_server_poll_recv(vn_server* s, uint8_t* buf, size_t cap, vn_recv* out);
int32_t vn_server_disconnect(vn_server* s, vn_conn conn, uint8_t reason);
int32_t vn_server_conn_stats(const vn_server* s, vn_conn conn, vn_conn_stats* out);
int32_t vn_server_conn_addr(const vn_server* s, vn_conn conn, vn_addr* out);
int32_t vn_server_stats(const vn_server* s, vn_server_stats* out);
uint32_t vn_server_slots_in_use(const vn_server* s);

/* ---- client --------------------------------------------------------------------------- */

int32_t vn_client_config_default(vn_client_config* cfg, uint64_t protocol_id);
size_t vn_client_size(void);
size_t vn_client_align(void);
int32_t vn_client_init(void* mem, size_t len, const vn_client_config* cfg);
/* random: 8 fresh random bytes from the OS. */
int32_t vn_client_connect(vn_client* c, const vn_addr* server, uint64_t random, uint64_t now_us);
void vn_client_handle_datagram(vn_client* c, const vn_addr* from, const uint8_t* data, size_t len,
                               uint64_t now_us);
/* Call every loop iteration: it also runs the client's timers. cap >= 1400. */
size_t vn_client_poll_transmit(vn_client* c, uint8_t* buf, size_t cap, vn_addr* to, uint64_t now_us);
uint64_t vn_client_next_deadline(const vn_client* c);
int32_t vn_client_poll_event(vn_client* c, vn_client_event* out);
int32_t vn_client_send(vn_client* c, uint8_t ch, const uint8_t* data, size_t len);
int32_t vn_client_poll_recv(vn_client* c, uint8_t* buf, size_t cap, uint8_t* ch, uint32_t* len);
void vn_client_disconnect(vn_client* c, uint8_t reason);
int32_t vn_client_is_connected(const vn_client* c);
int32_t vn_client_conn_stats(const vn_client* c, vn_conn_stats* out);

#ifdef __cplusplus
}
#endif

#endif /* VOIDNET_H */
