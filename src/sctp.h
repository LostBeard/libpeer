#ifndef SCTP_H_
#define SCTP_H_

#include "buffer.h"
#include "config.h"
#include "dtls_srtp.h"
#include "utils.h"

typedef enum DecpMsgType {

  DATA_CHANNEL_OPEN = 0x03,
  DATA_CHANNEL_ACK = 0x02,

} DecpMsgType;

typedef enum DataChannelPpid {

  DATA_CHANNEL_PPID_CONTROL = 50,
  DATA_CHANNEL_PPID_DOMSTRING = 51,
  DATA_CHANNEL_PPID_BINARY_PARTIAL = 52,
  DATA_CHANNEL_PPID_BINARY = 53,
  DATA_CHANNEL_PPID_DOMSTRING_PARTIAL = 54

} DataChannelPpid;

#if !CONFIG_USE_USRSCTP

typedef struct SctpChunkParam {
  uint16_t type;
  uint16_t length;
  uint8_t value[0];

} SctpChunkParam;

typedef enum SctpParamType {

  SCTP_PARAM_STATE_COOKIE = 7,
  SCTP_PARAM_FORWARD_TSN_SUPPORTED = 0xC000,  // RFC 3758

} SctpParamType;

typedef enum SctpHeaderType {

  SCTP_DATA = 0,
  SCTP_INIT = 1,
  SCTP_INIT_ACK = 2,
  SCTP_SACK = 3,
  SCTP_HEARTBEAT = 4,
  SCTP_HEARTBEAT_ACK = 5,
  SCTP_ABORT = 6,
  SCTP_SHUTDOWN = 7,
  SCTP_SHUTDOWN_ACK = 8,
  SCTP_ERROR = 9,
  SCTP_COOKIE_ECHO = 10,
  SCTP_COOKIE_ACK = 11,
  SCTP_ECNE = 12,
  SCTP_CWR = 13,
  SCTP_SHUTDOWN_COMPLETE = 14,
  SCTP_AUTH = 15,
  SCTP_ASCONF_ACK = 128,
  SCTP_ASCONF = 130,
  SCTP_FORWARD_TSN = 192

} SctpHeaderType;

typedef struct SctpChunkCommon {
  uint8_t type;
  uint8_t flags;
  uint16_t length;

} SctpChunkCommon;

typedef struct SctpForwardTsnChunk {
  SctpChunkCommon common;
  uint32_t new_cumulative_tsn;
  uint16_t stream_number;
  uint16_t stream_sequence_number;

} SctpForwardTsnChunk;

typedef struct SctpHeader {
  uint16_t source_port;
  uint16_t destination_port;
  uint32_t verification_tag;
  uint32_t checksum;

} SctpHeader;

typedef struct SctpPacket {
  SctpHeader header;
  uint8_t chunks[0];

} SctpPacket;

typedef struct SctpSackChunk {
  SctpChunkCommon common;
  uint32_t cumulative_tsn_ack;
  uint32_t a_rwnd;
  uint16_t number_of_gap_ack_blocks;
  uint16_t number_of_dup_tsns;
  uint8_t blocks[0];

} SctpSackChunk;

typedef struct SctpDataChunk {
  uint8_t type;
  uint8_t iube;
  uint16_t length;
  uint32_t tsn;
  uint16_t sid;
  uint16_t sqn;
  uint32_t ppid;
  uint8_t data[0];

} SctpDataChunk;

typedef struct SctpInitChunk {
  SctpChunkCommon common;
  uint32_t initiate_tag;
  uint32_t a_rwnd;
  uint16_t number_of_outbound_streams;
  uint16_t number_of_inbound_streams;
  uint32_t initial_tsn;
  SctpChunkParam param[0];

} SctpInitChunk;

typedef struct SctpCookieEchoChunk {
  SctpChunkCommon common;
  uint8_t cookie[0];
} SctpCookieEchoChunk;

#endif

typedef enum SctpDataPpid {

  PPID_CONTROL = 50,
  PPID_STRING = 51,
  PPID_BINARY = 53,
  PPID_STRING_EMPTY = 56,
  PPID_BINARY_EMPTY = 57

} SctpDataPpid;

#define SCTP_MAX_STREAMS 5

typedef struct {
  char label[32];  // Stream label
  uint16_t sid;    // Stream ID
} SctpStreamEntry;

/* SpawnDev: manual-SCTP send side. Every TSN in flight has an entry, so SACKs can be applied, chunks on reliable
   streams retransmitted (RFC 4960 6.3) and chunks on no-retransmit streams skipped with FORWARD-TSN (RFC 3758).
   Without this a single lost datagram was never repaired and left a permanent hole in the receiver's sequence. */
#define SCTP_TX_WINDOW 512        /* TSNs tracked (about 5 s of 15 fps video) */
#define SCTP_TX_STORE_SLOTS 24    /* packet copies kept for retransmission (reliable chunks only) */
#define SCTP_TRACKED_SIDS 32
#define SCTP_RTO_MIN_MS 400        /* above the peer's delayed-SACK window (up to 200 ms, RFC 4960 6.2) */
#define SCTP_RTO_MAX_MS 4800
#define SCTP_MAX_RETRANSMITS 10
#define SCTP_ABANDON_MS 500       /* no-retransmit chunk still unacked after this: skip it (FORWARD-TSN). Was 200: delayed SACKs made healthy chunks look lost */

typedef enum SctpTxState {
  SCTP_TX_FREE = 0,
  SCTP_TX_OUTSTANDING = 1,
  SCTP_TX_ACKED = 2,
  SCTP_TX_ABANDONED = 3,
} SctpTxState;

typedef struct SctpTxEntry {
  uint32_t tsn;
  uint32_t sent_ms;
  uint16_t len;     /* stored packet length */
  uint8_t state;    /* SctpTxState */
  uint8_t reliable;
  uint8_t retries;
  int8_t slot;      /* index into tx_store, -1 = not stored */
} SctpTxEntry;

typedef struct Sctp {
  struct socket* sock;

  int local_port;
  int remote_port;
  int connected;
  uint32_t verification_tag;
  uint32_t tsn;
  DtlsSrtp* dtls_srtp;
  Buffer** data_rb;
  int stream_count;
  SctpStreamEntry stream_table[SCTP_MAX_STREAMS];

  /* datachannel */
  void (*onmessage)(char* msg, size_t len, void* userdata, uint16_t sid);
  void (*onopen)(void* userdata);
  void (*onclose)(void* userdata);

  void* userdata;

  /* SpawnDev: manual-SCTP receive state (cumulative TSN + 64-TSN gap window, one reassembly). */
  int rx_tsn_valid;
  uint32_t rx_cum_tsn;
  uint64_t rx_gap_bits; /* bit i set = TSN rx_cum_tsn + 2 + i received out of order */
  uint8_t* rx_frag;
  size_t rx_frag_len;
  uint32_t rx_frag_next_tsn;
  uint16_t rx_frag_sid;
  uint32_t rx_frag_ppid;
  int rx_frag_active;

  /* SpawnDev: send side (see SctpTxEntry) */
  SctpTxEntry* tx;
  uint8_t* tx_store;
  uint32_t tx_store_used; /* bit per slot */
  uint32_t tx_base;       /* oldest TSN not cumulatively acked by the peer */
  int tx_valid;
  int peer_forward_tsn;   /* the peer advertised Forward-TSN support */
  uint8_t sid_unreliable[SCTP_TRACKED_SIDS];
  uint32_t tx_last_tick_ms;
  uint32_t tx_last_ftsn_ms;
  uint32_t stat_retransmits;
  uint32_t stat_abandoned;
  uint32_t stat_forward_tsn;
  uint32_t stat_unprotected;   /* reliable chunks sent while the store was full */
  uint32_t test_drop_permille; /* test hook: drop this share of outgoing DATA datagrams */
  uint32_t test_dropped;

  /* SpawnDev: association handshake retransmission (RFC 4960 T1-init / T1-cookie). The INIT and the COOKIE ECHO
   * were sent once; one lost datagram left the association half open and no data channel ever opened. */
  uint8_t hs_state;   /* 0 idle / done, 1 INIT sent (wait INIT-ACK), 2 COOKIE ECHO sent (wait COOKIE-ACK) */
  uint8_t hs_tries;
  uint16_t hs_len;
  uint32_t hs_sent_ms;
  uint8_t* hs_pkt;    /* the last INIT / COOKIE ECHO exactly as sent */
  uint32_t stat_hs_retransmits;

  uint8_t buf[CONFIG_MTU];
} Sctp;

int sctp_create_association(Sctp* sctp, DtlsSrtp* dtls_srtp);

void sctp_destroy_association(Sctp* sctp);

int sctp_is_connected(Sctp* sctp);

void sctp_incoming_data(Sctp* sctp, char* buf, size_t len);

int sctp_outgoing_data(Sctp* sctp, char* buf, size_t len, SctpDataPpid ppid, uint16_t sid);

/* SpawnDev: chunks on this stream are never retransmitted (a partial-reliability channel with 0 retransmits). */
void sctp_set_stream_unreliable(Sctp* sctp, uint16_t sid, int unreliable);

/* SpawnDev: retransmission / FORWARD-TSN timer; call from the connection loop. */
void sctp_tick(Sctp* sctp);

void sctp_onmessage(Sctp* sctp, void (*onmessage)(char* msg, size_t len, void* userdata, uint16_t sid));

void sctp_onopen(Sctp* sctp, void (*onopen)(void* userdata));

void sctp_onclose(Sctp* sctp, void (*onclose)(void* userdata));

#endif  // SCTP_H_
