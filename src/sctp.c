#include <stdlib.h>
#include <string.h>

#include "dtls_srtp.h"
#include "sctp.h"
#include "utils.h"
#include "ports.h"
#if CONFIG_USE_USRSCTP
#include <usrsctp.h>
#endif

static const uint32_t crc32c_table[256] = {
    0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
    0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
    0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
    0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
    0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
    0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
    0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
    0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
    0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
    0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
    0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
    0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
    0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
    0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
    0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
    0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
    0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
    0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
    0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
    0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
    0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
    0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
    0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
    0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
    0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
    0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
    0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
    0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
    0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
    0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
    0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
    0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
    0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
    0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
    0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
    0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
    0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
    0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
    0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
    0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
    0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
    0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
    0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
    0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
    0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
    0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
    0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
    0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
    0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
    0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
    0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
    0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
    0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
    0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
    0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
    0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
    0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
    0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
    0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
    0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
    0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
    0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
    0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
    0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L};

uint32_t crc32c(uint32_t crc, const uint8_t* data, unsigned int length) {
  while (length--) {
    crc = crc32c_table[(crc ^ *data++) & 0xFFL] ^ (crc >> 8);
  }
  return crc ^ 0xffffffff;
}

static uint32_t sctp_get_checksum(Sctp* sctp, const uint8_t* buf, size_t len) {
  uint32_t crc = crc32c(0xffffffff, buf, len);
  return crc;
}

static int sctp_outgoing_data_cb(void* userdata, void* buf, size_t len, uint8_t tos, uint8_t set_df) {
  Sctp* sctp = (Sctp*)userdata;

  dtls_srtp_write(sctp->dtls_srtp, buf, len);
  return 0;
}

#if !CONFIG_USE_USRSCTP
// ---- SpawnDev: send side (SACK processing, retransmission, FORWARD-TSN). See SctpTxEntry in sctp.h. ----

// TSN serial-number arithmetic (RFC 1982): wraps at 2^32.
#define TSN_LT(a, b) ((int32_t)((uint32_t)(a) - (uint32_t)(b)) < 0)
#define TSN_LE(a, b) ((int32_t)((uint32_t)(a) - (uint32_t)(b)) <= 0)

static void sctp_tx_free_slot(Sctp* sctp, SctpTxEntry* e) {
  if (e->slot >= 0) {
    sctp->tx_store_used &= ~(1u << e->slot);
    e->slot = -1;
  }
}

static void sctp_tx_reset(Sctp* sctp) {
  if (sctp->tx == NULL) {
    sctp->tx = (SctpTxEntry*)calloc(SCTP_TX_WINDOW, sizeof(SctpTxEntry));
  }
  if (sctp->tx_store == NULL) {
    sctp->tx_store = (uint8_t*)malloc(SCTP_TX_STORE_SLOTS * CONFIG_MTU);
  }
  if (sctp->tx) {
    memset(sctp->tx, 0, SCTP_TX_WINDOW * sizeof(SctpTxEntry));
    for (int i = 0; i < SCTP_TX_WINDOW; i++) sctp->tx[i].slot = -1;
  }
  sctp->tx_store_used = 0;
  sctp->tx_base = sctp->tsn;
  sctp->tx_valid = sctp->tx != NULL;
  sctp->peer_forward_tsn = 0;
  sctp->tx_last_tick_ms = 0;
  sctp->tx_last_ftsn_ms = 0;
}

// Records one DATA chunk just before it goes out. Reliable chunks keep a copy of the whole packet (it is resent
// unchanged: same TSN, same checksum) while store slots last.
static void sctp_tx_record(Sctp* sctp, uint32_t tsn, int reliable, const uint8_t* packet, size_t len) {
  if (!sctp->tx_valid) return;
  SctpTxEntry* e = &sctp->tx[tsn % SCTP_TX_WINDOW];
  if (e->state == SCTP_TX_OUTSTANDING && e->tsn != tsn) {
    // The window wrapped over a chunk the peer never acknowledged: give it up.
    sctp->stat_abandoned++;
  }
  sctp_tx_free_slot(sctp, e);
  e->tsn = tsn;
  e->sent_ms = ports_get_epoch_time();
  e->state = SCTP_TX_OUTSTANDING;
  e->retries = 0;
  e->len = (uint16_t)len;
  e->reliable = 0;
  if (reliable) {
    for (int i = 0; i < SCTP_TX_STORE_SLOTS && sctp->tx_store; i++) {
      if (!(sctp->tx_store_used & (1u << i))) {
        sctp->tx_store_used |= (1u << i);
        memcpy(sctp->tx_store + i * CONFIG_MTU, packet, len);
        e->slot = (int8_t)i;
        e->reliable = 1;
        break;
      }
    }
    if (!e->reliable) sctp->stat_unprotected++;
  }
}

// Sends a finished DATA packet: records it, then writes it (or, in a loss test, pretends it was lost on the way).
static void sctp_tx_send_data_packet(Sctp* sctp, uint32_t tsn, int reliable, uint8_t* packet, size_t len) {
  sctp_tx_record(sctp, tsn, reliable, packet, len);
  if (sctp->test_drop_permille > 0) {
    static uint32_t lcg = 0x2545F491u;
    lcg = lcg * 1664525u + 1013904223u;
    if ((lcg >> 8) % 1000 < sctp->test_drop_permille) {
      sctp->test_dropped++;
      return;
    }
  }
  sctp_outgoing_data_cb(sctp, packet, len, 0, 0);
}

static void sctp_tx_on_sack(Sctp* sctp, SctpSackChunk* sack, size_t chunk_len) {
  if (!sctp->tx_valid || chunk_len < sizeof(SctpSackChunk)) return;
  uint32_t cum = ntohl(sack->cumulative_tsn_ack);
  if (!TSN_LT(cum, sctp->tsn)) return;  // acknowledges a TSN never sent: ignore the whole SACK
  if (!TSN_LT(cum, sctp->tx_base)) {    // cum >= tx_base: the cumulative point moved
    for (uint32_t t = sctp->tx_base; TSN_LE(t, cum); t++) {
      SctpTxEntry* e = &sctp->tx[t % SCTP_TX_WINDOW];
      if (e->tsn == t) {
        sctp_tx_free_slot(sctp, e);
        e->state = SCTP_TX_FREE;
      }
    }
    sctp->tx_base = cum + 1;
  }
  // Gap ack blocks: [start, end] offsets from the cumulative TSN.
  int blocks = ntohs(sack->number_of_gap_ack_blocks);
  if (sizeof(SctpSackChunk) + (size_t)blocks * 4 > chunk_len) return;
  for (int i = 0; i < blocks; i++) {
    uint16_t start = ntohs(*(uint16_t*)(sack->blocks + i * 4));
    uint16_t end = ntohs(*(uint16_t*)(sack->blocks + i * 4 + 2));
    for (uint32_t off = start; off <= end && off < SCTP_TX_WINDOW; off++) {
      uint32_t t = cum + off;
      SctpTxEntry* e = &sctp->tx[t % SCTP_TX_WINDOW];
      if (e->tsn == t && e->state != SCTP_TX_FREE) {
        sctp_tx_free_slot(sctp, e);
        e->state = SCTP_TX_ACKED;
      }
    }
  }
}

static void sctp_send_forward_tsn(Sctp* sctp, uint32_t new_cum_tsn) {
  // Header + one FORWARD-TSN chunk with no stream entries: every chunk we send is unordered, and RFC 3758 needs
  // stream/sequence pairs only for ordered ones.
  uint8_t pkt[sizeof(SctpHeader) + 8];
  memset(pkt, 0, sizeof(pkt));
  SctpHeader* h = (SctpHeader*)pkt;
  h->source_port = htons(sctp->local_port);
  h->destination_port = htons(sctp->remote_port);
  h->verification_tag = sctp->verification_tag;
  uint8_t* c = pkt + sizeof(SctpHeader);
  c[0] = SCTP_FORWARD_TSN;
  c[1] = 0;
  *(uint16_t*)(c + 2) = htons(8);
  *(uint32_t*)(c + 4) = htonl(new_cum_tsn);
  h->checksum = 0;
  h->checksum = sctp_get_checksum(sctp, pkt, sizeof(pkt));
  dtls_srtp_write(sctp->dtls_srtp, pkt, sizeof(pkt));
  sctp->stat_forward_tsn++;
}
#endif

void sctp_set_stream_unreliable(Sctp* sctp, uint16_t sid, int unreliable) {
  if (sctp && sid < SCTP_TRACKED_SIDS) sctp->sid_unreliable[sid] = unreliable ? 1 : 0;
}

#if !CONFIG_USE_USRSCTP
#define SCTP_HS_RTO_MS 1000
#define SCTP_HS_MAX_TRIES 8

// SpawnDev: keeps the handshake packet just sent (INIT or COOKIE ECHO) for sctp_tick to resend.
static void sctp_hs_remember(Sctp* sctp, int state, const uint8_t* pkt, int len) {
  if (len <= 0 || len > CONFIG_MTU) return;
  if (!sctp->hs_pkt) sctp->hs_pkt = (uint8_t*)malloc(CONFIG_MTU);
  if (!sctp->hs_pkt) return;
  memcpy(sctp->hs_pkt, pkt, len);
  sctp->hs_len = (uint16_t)len;
  sctp->hs_state = (uint8_t)state;
  sctp->hs_tries = 0;
  sctp->hs_sent_ms = ports_get_epoch_time();
}
#endif

void sctp_tick(Sctp* sctp) {
#if !CONFIG_USE_USRSCTP
  if (sctp && sctp->hs_state && sctp->hs_pkt) {
    // T1-init / T1-cookie: resend until the INIT-ACK / COOKIE-ACK comes, doubling the wait, then give up (the
    // managed side's channel-open timeout reports the failure).
    uint32_t hs_now = ports_get_epoch_time();
    uint32_t rto = SCTP_HS_RTO_MS << (sctp->hs_tries < 3 ? sctp->hs_tries : 3);
    if (hs_now - sctp->hs_sent_ms >= rto) {
      if (sctp->hs_tries >= SCTP_HS_MAX_TRIES) {
        sctp->hs_state = 0;
      } else {
        dtls_srtp_write(sctp->dtls_srtp, sctp->hs_pkt, sctp->hs_len);
        sctp->hs_tries++;
        sctp->hs_sent_ms = hs_now;
        sctp->stat_hs_retransmits++;
      }
    }
  }
  if (!sctp || !sctp->connected || !sctp->tx_valid) return;
  uint32_t now = ports_get_epoch_time();
  if (now - sctp->tx_last_tick_ms < 10) return;
  sctp->tx_last_tick_ms = now;

  int scanned = 0;
  for (uint32_t t = sctp->tx_base; TSN_LT(t, sctp->tsn) && scanned < SCTP_TX_WINDOW; t++, scanned++) {
    SctpTxEntry* e = &sctp->tx[t % SCTP_TX_WINDOW];
    if (e->tsn != t || e->state != SCTP_TX_OUTSTANDING) continue;
    uint32_t age = now - e->sent_ms;
    if (e->reliable && e->slot >= 0) {
      uint32_t rto = SCTP_RTO_MIN_MS << (e->retries < 4 ? e->retries : 4);
      if (rto > SCTP_RTO_MAX_MS) rto = SCTP_RTO_MAX_MS;
      if (age >= rto) {
        if (e->retries >= SCTP_MAX_RETRANSMITS) {
          sctp_tx_free_slot(sctp, e);
          e->state = SCTP_TX_ABANDONED;
          sctp->stat_abandoned++;
        } else {
          dtls_srtp_write(sctp->dtls_srtp, sctp->tx_store + e->slot * CONFIG_MTU, e->len);
          e->retries++;
          e->sent_ms = now;
          sctp->stat_retransmits++;
        }
      }
    } else if (age >= SCTP_ABANDON_MS) {
      e->state = SCTP_TX_ABANDONED;  // a no-retransmit chunk (video): too late to matter
      sctp->stat_abandoned++;
    }
  }

  // FORWARD-TSN past the leading run of chunks the peer acknowledged out of order or we gave up on, so its
  // cumulative TSN keeps moving. Without Forward-TSN support on the peer, the gap simply stays (old behaviour).
  if (sctp->peer_forward_tsn && now - sctp->tx_last_ftsn_ms >= 100) {
    uint32_t fwd = sctp->tx_base - 1;
    int moved = 0;
    for (uint32_t t = sctp->tx_base; TSN_LT(t, sctp->tsn); t++) {
      SctpTxEntry* e = &sctp->tx[t % SCTP_TX_WINDOW];
      if (e->tsn != t || (e->state != SCTP_TX_ACKED && e->state != SCTP_TX_ABANDONED)) break;
      fwd = t;
      moved = 1;
    }
    // Only worth sending when an abandoned chunk is involved; a run of acked chunks moves with the next SACK.
    if (moved) {
      int any_abandoned = 0;
      for (uint32_t t = sctp->tx_base; TSN_LE(t, fwd); t++) {
        if (sctp->tx[t % SCTP_TX_WINDOW].state == SCTP_TX_ABANDONED) {
          any_abandoned = 1;
          break;
        }
      }
      if (any_abandoned) {
        sctp_send_forward_tsn(sctp, fwd);
        sctp->tx_last_ftsn_ms = now;
      }
    }
  }
#endif
}

int sctp_outgoing_data(Sctp* sctp, char* buf, size_t len, SctpDataPpid ppid, uint16_t sid) {
#if CONFIG_USE_USRSCTP
  int res;
  struct sctp_sendv_spa spa = {0};

  spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;

  spa.sendv_sndinfo.snd_sid = sid;
  spa.sendv_sndinfo.snd_flags = SCTP_EOR;
  spa.sendv_sndinfo.snd_ppid = htonl(ppid);

  res = usrsctp_sendv(sctp->sock, buf, len, NULL, 0, &spa, sizeof(spa), SCTP_SENDV_SPA, 0);
  if (res < 0) {
    LOGE("sctp sendv error %d: %s", errno, strerror(errno));
  }
  return res;
#else
  size_t padding_len = 0;
  size_t payload_max = SCTP_MTU - sizeof(SctpPacket) - sizeof(SctpDataChunk);
  size_t pos = 0;
  static uint16_t sqn = 0;
  // SpawnDev: control (DCEP) messages and reliable streams are retransmitted until acknowledged; streams opened with
  // 0 retransmits (video) are not, and get skipped with FORWARD-TSN instead.
  int reliable = ppid == PPID_CONTROL || sid >= SCTP_TRACKED_SIDS || !sctp->sid_unreliable[sid];

  SctpPacket* packet = (SctpPacket*)(sctp->buf);
  SctpDataChunk* chunk = (SctpDataChunk*)(packet->chunks);

  packet->header.source_port = htons(sctp->local_port);
  packet->header.destination_port = htons(sctp->remote_port);
  packet->header.verification_tag = sctp->verification_tag;

  chunk->type = SCTP_DATA;
  chunk->iube = 0x06;
  // SpawnWear (Phase 7b): honor the caller's stream id instead of hardcoding 0. The manual SCTP
  // path (this build doesn't use usrsctp - INIT tag 0x12345678 confirms) was pinning every DATA
  // chunk to stream 0, so our DTLS-server data channel (which must live on an ODD stream per
  // RFC 8832 §6) was emitted on stream 0 and SipSorcery/Chrome dropped it ("no channel for sid 0").
  chunk->sid = htons(sid);
  chunk->sqn = htons(sqn++);
  chunk->ppid = htonl(ppid);

  while (len > payload_max) {
    chunk->length = htons(payload_max + sizeof(SctpDataChunk));
    chunk->tsn = htonl(sctp->tsn++);
    memcpy(chunk->data, buf + pos, payload_max);
    packet->header.checksum = 0;

    packet->header.checksum = sctp_get_checksum(sctp, (const uint8_t*)sctp->buf, SCTP_MTU);

    sctp_tx_send_data_packet(sctp, ntohl(chunk->tsn), reliable, sctp->buf, SCTP_MTU);
    chunk->iube = 0x04;
    len -= payload_max;
    pos += payload_max;
  }

  if (len > 0) {
    chunk->length = htons(len + sizeof(SctpDataChunk));
    chunk->iube++;
    chunk->tsn = htonl(sctp->tsn++);
    memset(chunk->data, 0, payload_max);
    memcpy(chunk->data, buf + pos, len);
    packet->header.checksum = 0;

    padding_len = 4 * ((len + sizeof(SctpDataChunk) + sizeof(SctpPacket) + 3) / 4);

    packet->header.checksum = sctp_get_checksum(sctp, (const uint8_t*)sctp->buf, padding_len);

    sctp_tx_send_data_packet(sctp, ntohl(chunk->tsn), reliable, sctp->buf, padding_len);
  }
#endif
  return len;
}

void sctp_add_stream_mapping(Sctp* sctp, const char* label, uint16_t sid) {
  if (sctp->stream_count < SCTP_MAX_STREAMS) {
    strncpy(sctp->stream_table[sctp->stream_count].label, label, sizeof(sctp->stream_table[sctp->stream_count].label));
    sctp->stream_table[sctp->stream_count].sid = sid;
    sctp->stream_count++;
  } else
    LOGE("Stream table full. Cannot add more streams.");
}

void sctp_parse_data_channel_open(Sctp* sctp, uint16_t sid, char* data, size_t length) {
  if (length < 12)
    return;  // Not enough data for a DATA_CHANNEL_OPEN message

  if (data[0] == DATA_CHANNEL_OPEN) {
    uint16_t label_length = ntohs(*(uint16_t*)(data + 8));
    uint16_t protocol_length = ntohs(*(uint16_t*)(data + 10));

    // Ensure we have enough data for the label and protocol
    if (length < 12 + label_length + protocol_length)
      return;

    char* label = (char*)(data + 12);

    // copy and null-terminate
    char label_str[label_length + 1];
    memcpy(label_str, label, label_length);
    label_str[label_length] = '\0';

    // Log or process the DATA_CHANNEL_OPEN message
    printf("DATA_CHANNEL_OPEN: Label=%s, sid=%d\n", label_str, sid);

    // Add stream mapping
    sctp_add_stream_mapping(sctp, label_str, sid);
    char ack = DATA_CHANNEL_ACK;
    sctp_outgoing_data(sctp, &ack, 1, DATA_CHANNEL_PPID_CONTROL, sid);
  }
}

void sctp_handle_sctp_packet(Sctp* sctp, char* buf, size_t len) {
  if (len <= 29)
    return;

  if (buf[12] != 0)  // if chunk_type is no zero, it's not data
    return;

  uint16_t sid = ntohs(*(uint16_t*)(buf + 20));
  uint32_t ppid = ntohl(*(uint32_t*)(buf + 24));

  if (ppid == DATA_CHANNEL_PPID_CONTROL)
    sctp_parse_data_channel_open(sctp, sid, buf + 28, len - 28);
}

#if !CONFIG_USE_USRSCTP
#define SCTP_RX_MAX_MESSAGE (64 * 1024)

static void sctp_rx_deliver(Sctp* sctp, uint32_t ppid, uint16_t sid, uint8_t* data, size_t len,
                            uint16_t* dcep_ack_sid, int* dcep_ack_pending) {
  if (ppid == DATA_CHANNEL_PPID_CONTROL) {
    if (len >= 12 && data[0] == DATA_CHANNEL_OPEN) {
      uint16_t label_length = ntohs(*(uint16_t*)(data + 8));
      if (12 + (size_t)label_length <= len) {
        char label[32];
        size_t n = label_length < sizeof(label) - 1 ? label_length : sizeof(label) - 1;
        memcpy(label, data + 12, n);
        label[n] = 0;
        sctp_add_stream_mapping(sctp, label, sid);
      }
      *dcep_ack_sid = sid;
      *dcep_ack_pending = 1;
    }
    return;
  }
  if (ppid == DATA_CHANNEL_PPID_DOMSTRING || ppid == DATA_CHANNEL_PPID_BINARY ||
      ppid == DATA_CHANNEL_PPID_DOMSTRING_PARTIAL || ppid == DATA_CHANNEL_PPID_BINARY_PARTIAL) {
    if (sctp->onmessage)
      sctp->onmessage((char*)data, len, sctp->userdata, sid);
  }
  // empty-message PPIDs carry nothing to deliver
}

// Records a TSN. Returns 1 if new, 0 if a duplicate (already received: ack it, never deliver twice).
static int sctp_rx_track_tsn(Sctp* sctp, uint32_t tsn) {
  if (!sctp->rx_tsn_valid) {
    sctp->rx_cum_tsn = tsn - 1;
    sctp->rx_gap_bits = 0;
    sctp->rx_tsn_valid = 1;
  }
  int32_t ahead = (int32_t)(tsn - sctp->rx_cum_tsn);
  if (ahead <= 0)
    return 0;
  if (ahead == 1) {
    sctp->rx_cum_tsn = tsn;
    while (sctp->rx_gap_bits & 1) {  // close any gap this TSN filled
      sctp->rx_gap_bits >>= 1;
      sctp->rx_cum_tsn++;
    }
    sctp->rx_gap_bits >>= 1;
    return 1;
  }
  int bit = ahead - 2;
  if (bit >= 64)
    return 1;  // beyond the gap window: deliver; the SACK makes the peer resend the gap later
  if (sctp->rx_gap_bits & ((uint64_t)1 << bit))
    return 0;
  sctp->rx_gap_bits |= ((uint64_t)1 << bit);
  return 1;
}

static void sctp_rx_data_chunk(Sctp* sctp, SctpDataChunk* chunk, uint16_t* dcep_ack_sid, int* dcep_ack_pending) {
  size_t chunk_len = ntohs(chunk->length);
  if (chunk_len < sizeof(SctpDataChunk))
    return;
  size_t data_len = chunk_len - sizeof(SctpDataChunk);
  uint32_t tsn = ntohl(chunk->tsn);
  uint16_t sid = ntohs(chunk->sid);
  uint32_t ppid = ntohl(chunk->ppid);
  int begin = (chunk->iube & 0x02) != 0;
  int end = (chunk->iube & 0x01) != 0;

  if (!sctp_rx_track_tsn(sctp, tsn))
    return;

  if (begin && end) {
    sctp_rx_deliver(sctp, ppid, sid, chunk->data, data_len, dcep_ack_sid, dcep_ack_pending);
    return;
  }

  // Fragmented message: reassembled when fragments arrive in TSN order (the normal case). A fragment out of
  // order drops the partial message (control messages are small, so reliable channels rarely fragment).
  if (begin) {
    if (!sctp->rx_frag) {
      sctp->rx_frag = (uint8_t*)malloc(SCTP_RX_MAX_MESSAGE);
      if (!sctp->rx_frag)
        return;
    }
    sctp->rx_frag_len = 0;
    sctp->rx_frag_sid = sid;
    sctp->rx_frag_ppid = ppid;
    sctp->rx_frag_active = 1;
  } else if (!sctp->rx_frag_active || tsn != sctp->rx_frag_next_tsn || sid != sctp->rx_frag_sid) {
    sctp->rx_frag_active = 0;
    return;
  }
  if (sctp->rx_frag_len + data_len > SCTP_RX_MAX_MESSAGE) {
    LOGE("sctp: message larger than %d bytes dropped", SCTP_RX_MAX_MESSAGE);
    sctp->rx_frag_active = 0;
    return;
  }
  memcpy(sctp->rx_frag + sctp->rx_frag_len, chunk->data, data_len);
  sctp->rx_frag_len += data_len;
  sctp->rx_frag_next_tsn = tsn + 1;
  if (end) {
    sctp->rx_frag_active = 0;
    sctp_rx_deliver(sctp, sctp->rx_frag_ppid, sctp->rx_frag_sid, sctp->rx_frag, sctp->rx_frag_len,
                    dcep_ack_sid, dcep_ack_pending);
  }
}

static void sctp_send_sack(Sctp* sctp) {
  SctpPacket* out_packet = (SctpPacket*)sctp->buf;
  SctpSackChunk* sack = (SctpSackChunk*)out_packet->chunks;
  memset(sctp->buf, 0, sizeof(SctpHeader) + sizeof(SctpSackChunk) + 16 * 4);

  // Gap ack blocks: runs of set bits, offsets relative to the cumulative TSN (bit i = offset i + 2).
  uint16_t* blocks = (uint16_t*)sack->blocks;
  int nblocks = 0;
  uint64_t bits = sctp->rx_gap_bits;
  for (int i = 0; i < 64 && nblocks < 16;) {
    if (!(bits & ((uint64_t)1 << i))) {
      i++;
      continue;
    }
    int start = i;
    while (i < 64 && (bits & ((uint64_t)1 << i)))
      i++;
    blocks[nblocks * 2] = htons((uint16_t)(start + 2));
    blocks[nblocks * 2 + 1] = htons((uint16_t)(i - 1 + 2));
    nblocks++;
  }

  sack->common.type = SCTP_SACK;
  sack->common.flags = 0x00;
  sack->common.length = htons(16 + nblocks * 4);
  sack->cumulative_tsn_ack = htonl(sctp->rx_cum_tsn);
  sack->a_rwnd = htonl(SCTP_RX_MAX_MESSAGE);  // every message goes straight to the app
  sack->number_of_gap_ack_blocks = htons(nblocks);
  sack->number_of_dup_tsns = 0;

  size_t length = sizeof(SctpHeader) + 16 + nblocks * 4;
  out_packet->header.source_port = htons(sctp->local_port);
  out_packet->header.destination_port = htons(sctp->remote_port);
  out_packet->header.verification_tag = sctp->verification_tag;
  out_packet->header.checksum = 0x00;
  out_packet->header.checksum = sctp_get_checksum(sctp, sctp->buf, length);
  dtls_srtp_write(sctp->dtls_srtp, sctp->buf, length);
}
#endif

#if !CONFIG_USE_USRSCTP
// SpawnDev: finds a parameter in an INIT / INIT-ACK chunk (parameters follow the 20-byte fixed part, 4-byte padded).
static SctpChunkParam* sctp_init_find_param(SctpInitChunk* chunk, size_t chunk_len, uint16_t type) {
  size_t off = 20;
  while (off + 4 <= chunk_len) {
    SctpChunkParam* p = (SctpChunkParam*)((uint8_t*)chunk + off);
    uint16_t plen = ntohs(p->length);
    if (plen < 4 || off + plen > chunk_len) return NULL;
    if (ntohs(p->type) == type) return p;
    off += (plen + 3) & ~3u;
  }
  return NULL;
}
#endif

void sctp_incoming_data(Sctp* sctp, char* buf, size_t len) {
  if (!sctp)
    return;

#if CONFIG_USE_USRSCTP
  sctp_handle_sctp_packet(sctp, buf, len);
  usrsctp_conninput(sctp, buf, len, 0);
#else
  size_t length = 0;
  size_t pos = sizeof(SctpHeader);
  SctpChunkCommon* chunk_common;
  SctpPacket* in_packet = (SctpPacket*)buf;
  SctpPacket* out_packet = (SctpPacket*)sctp->buf;

  // Header
#if 0
  LOGD("source_port %d", ntohs(in_packet->header.source_port));
  LOGD("destination_port %d", ntohs(in_packet->header.destination_port));
  LOGD("verification_tag %ld", ntohl(in_packet->header.verification_tag));
  LOGD("checksum %d", ntohs(in_packet->header.checksum));
#endif
  uint32_t crc32c = in_packet->header.checksum;

  in_packet->header.checksum = 0;

  if (crc32c != sctp_get_checksum(sctp, (const uint8_t*)buf, len)) {
    LOGE("checksum error");
    return;
  }

  int need_sack = 0;
  int dcep_ack_pending = 0;
  uint16_t dcep_ack_sid = 0;

  // prepare outgoing packet
  memset(sctp->buf, 0, sizeof(sctp->buf));
  while (pos + sizeof(SctpChunkCommon) <= len) {
    chunk_common = (SctpChunkCommon*)(buf + pos);
    size_t chunk_len = ntohs(chunk_common->length);
    if (chunk_len < sizeof(SctpChunkCommon) || pos + chunk_len > len)
      break;  // malformed: stop rather than loop forever or read past the packet

    // SpawnDev: DATA or SACK from the peer means it took our COOKIE ECHO even if its COOKIE-ACK was lost.
    if (sctp->hs_state == 2 && (chunk_common->type == SCTP_DATA || chunk_common->type == SCTP_SACK)) {
      sctp->hs_state = 0;
    }

    switch (chunk_common->type) {
      case SCTP_DATA: {
        // SpawnDev: every DATA chunk in the packet is processed (Chrome bundles small messages), fragments are
        // reassembled, and ONE SACK with the true cumulative TSN + gap blocks is sent after the loop. The old code
        // handled only the first chunk, delivered fragments as separate messages, acked any TSN as cumulative and
        // advertised a 2-byte window.
        sctp_rx_data_chunk(sctp, (SctpDataChunk*)(buf + pos), &dcep_ack_sid, &dcep_ack_pending);
        need_sack = 1;
        length = 0;
      } break;
      case SCTP_INIT: {
        LOGD("SCTP_INIT");

        SctpInitChunk* init_chunk;
        init_chunk = (SctpInitChunk*)(buf + pos);
        sctp->verification_tag = init_chunk->initiate_tag;
        sctp->rx_cum_tsn = ntohl(init_chunk->initial_tsn) - 1;
        sctp->rx_gap_bits = 0;
        sctp->rx_tsn_valid = 1;
        sctp->peer_forward_tsn = sctp_init_find_param(init_chunk, chunk_len, SCTP_PARAM_FORWARD_TSN_SUPPORTED) != NULL;

        SctpInitChunk* init_ack = (SctpInitChunk*)out_packet->chunks;
        init_ack->common.type = SCTP_INIT_ACK;
        init_ack->common.flags = 0x00;
        init_ack->common.length = htons(20 + 8 + 4);
        init_ack->initiate_tag = htonl(0x12345678);
        init_ack->a_rwnd = htonl(0x100000);
        init_ack->number_of_outbound_streams = 0xffff;
        init_ack->number_of_inbound_streams = 0xffff;
        init_ack->initial_tsn = htonl(sctp->tsn);

        SctpChunkParam* param = init_ack->param;

        param->type = htons(SCTP_PARAM_STATE_COOKIE);
        param->length = htons(8);
        *(uint32_t*)&param->value = htonl(0x02);
        // SpawnDev: we can skip abandoned chunks (FORWARD-TSN), so say so (RFC 3758 3.3.1).
        SctpChunkParam* ftsn = (SctpChunkParam*)((uint8_t*)param + 8);
        ftsn->type = htons(SCTP_PARAM_FORWARD_TSN_SUPPORTED);
        ftsn->length = htons(4);
        length = ntohs(init_ack->common.length) + sizeof(SctpHeader);

        if (!sctp->connected) {
          sctp->connected = 1;
          if (sctp->onopen) {
            sctp->onopen(sctp->userdata);
          }
        }
      } break;
      case SCTP_INIT_ACK: {
        SctpInitChunk* init_ack = (SctpInitChunk*)(buf + pos);
        if (sctp->hs_state == 2) {
          // A duplicate INIT-ACK (our INIT was resent): the COOKIE ECHO already went out and is on its own timer.
          length = 0;
          break;
        }
        sctp->hs_state = 0;
        SctpCookieEchoChunk* cookie_echo = (SctpCookieEchoChunk*)out_packet->chunks;
        sctp->rx_cum_tsn = ntohl(init_ack->initial_tsn) - 1;
        sctp->rx_gap_bits = 0;
        sctp->rx_tsn_valid = 1;
        sctp->verification_tag = init_ack->initiate_tag;
        sctp->peer_forward_tsn = sctp_init_find_param(init_ack, chunk_len, SCTP_PARAM_FORWARD_TSN_SUPPORTED) != NULL;
        SctpChunkParam* param = sctp_init_find_param(init_ack, chunk_len, SCTP_PARAM_STATE_COOKIE);
        if (param == NULL || ntohs(param->length) < 4 || ntohs(param->length) - 4 + sizeof(SctpHeader) + 4 > sizeof(sctp->buf)) {
          LOGE("INIT-ACK without a usable state cookie");
          length = 0;
          break;
        }

        cookie_echo->common.type = SCTP_COOKIE_ECHO;
        cookie_echo->common.flags = 0x00;
        // cookie echo: type + flag + length (4 bytes) + cookie
        cookie_echo->common.length = htons(ntohs(param->length));
        // param: type + length (4 bytes) + cookie
        memcpy(cookie_echo->cookie, param->value, ntohs(param->length) - 4);
        length = ntohs(cookie_echo->common.length) + sizeof(SctpHeader);

        if (!sctp->connected) {
          sctp->connected = 1;
          if (sctp->onopen) {
            sctp->onopen(sctp->userdata);
          }
        }
      } break;
      case SCTP_SACK:
        // SpawnDev: apply the peer's acknowledgements (frees retransmission copies, moves the send window).
        sctp_tx_on_sack(sctp, (SctpSackChunk*)(buf + pos), chunk_len);
        length = 0;
        break;
      case SCTP_HEARTBEAT: {
        // SpawnDev: answer heartbeats (RFC 4960 8.3). Unanswered ones make the peer declare the path dead after a few
        // tries, which ended long sessions. The ACK echoes the Heartbeat Info parameter unchanged.
        if (chunk_len + sizeof(SctpHeader) <= sizeof(sctp->buf)) {
          memcpy(out_packet->chunks, buf + pos, chunk_len);
          ((SctpChunkCommon*)out_packet->chunks)->type = SCTP_HEARTBEAT_ACK;
          length = chunk_len + sizeof(SctpHeader);
        } else {
          length = 0;
        }
      } break;
      case SCTP_COOKIE_ECHO: {
        LOGD("SCTP_COOKIE_ECHO");
        SctpChunkCommon* common = (SctpChunkCommon*)out_packet->chunks;
        common->type = SCTP_COOKIE_ACK;
        common->length = htons(4);
        length = ntohs(common->length) + sizeof(SctpHeader);
        pos = len;  // Do not handle other msg
      } break;
      case SCTP_COOKIE_ACK: {
        sctp->hs_state = 0;  // SpawnDev: the association is up; stop resending the COOKIE ECHO
        break;
      }
      case SCTP_ABORT:
        sctp->connected = 0;
        if (sctp->onclose) {
          sctp->onclose(sctp->userdata);
        }
        break;
      default:
        LOGI("Unknown chunk type %d", chunk_common->type);
        length = 0;
        break;
    }

    out_packet->header.source_port = htons(sctp->local_port);
    out_packet->header.destination_port = htons(sctp->remote_port);
    out_packet->header.verification_tag = sctp->verification_tag;
    out_packet->header.checksum = 0x00;

    if (length > 0) {
      // padding 4
      length = (4 * ((length + 3) / 4));
      out_packet->header.checksum = sctp_get_checksum(sctp, sctp->buf, length);
      dtls_srtp_write(sctp->dtls_srtp, sctp->buf, length);
      if (((SctpChunkCommon*)out_packet->chunks)->type == SCTP_COOKIE_ECHO) {
        sctp_hs_remember(sctp, 2, sctp->buf, length);  // SpawnDev: resent by sctp_tick until COOKIE-ACK
      }
      // sctp_outgoing_data_cb(sctp, sctp->buf, SCTP_MTU, 0, 0);
    }
    if (pos >= len)
      break;  // a handler consumed the rest of the packet
    pos += (chunk_len + 3) & ~(size_t)3;  // chunks are padded to 4 bytes
  }

  if (need_sack)
    sctp_send_sack(sctp);
  if (dcep_ack_pending) {
    char ack = DATA_CHANNEL_ACK;
    sctp_outgoing_data(sctp, &ack, 1, PPID_CONTROL, dcep_ack_sid);
  }
#endif
}

static int sctp_handle_incoming_data(Sctp* sctp, char* data, size_t len, uint32_t ppid, uint16_t sid, int flags) {
#if CONFIG_USE_USRSCTP
  switch (ppid) {
    case DATA_CHANNEL_PPID_CONTROL:
      break;

    case DATA_CHANNEL_PPID_DOMSTRING:
    case DATA_CHANNEL_PPID_BINARY:
    case DATA_CHANNEL_PPID_DOMSTRING_PARTIAL:
    case DATA_CHANNEL_PPID_BINARY_PARTIAL:

      LOGD("Got message (size = %ld)", len);
      if (sctp->onmessage) {
        sctp->onmessage(data, len, sctp->userdata, sid);
      }
      break;

    default:
      break;
  }
#endif
  return 0;
}

#if CONFIG_USE_USRSCTP

static void sctp_process_notification(Sctp* sctp, union sctp_notification* notification, size_t len) {
  if (notification->sn_header.sn_length != (uint32_t)len) {
    return;
  }

  switch (notification->sn_header.sn_type) {
    case SCTP_ASSOC_CHANGE:

      switch (notification->sn_assoc_change.sac_state) {
        case SCTP_COMM_UP:

          sctp->connected = 1;
          if (sctp->onopen) {
            sctp->onopen(sctp->userdata);
          }

          break;

        case SCTP_COMM_LOST:
        case SCTP_SHUTDOWN_COMP:
          sctp->connected = 0;
          if (sctp->onclose) {
            sctp->onclose(sctp->userdata);
          }
        default:
          break;
      }
      break;
    default:
      break;
  }
}

static int sctp_incoming_data_cb(struct socket* sock, union sctp_sockstore addr, void* data, size_t len, struct sctp_rcvinfo recv_info, int flags, void* userdata) {
  Sctp* sctp = (Sctp*)userdata;
  LOGD("Data of length %u received on stream %u with SSN %u, TSN %u, PPID %u",
       (uint32_t)len,
       recv_info.rcv_sid,
       recv_info.rcv_ssn,
       recv_info.rcv_tsn,
       ntohl(recv_info.rcv_ppid));
  if (flags & MSG_NOTIFICATION) {
    sctp_process_notification(sctp, (union sctp_notification*)data, len);
  } else {
    sctp_handle_incoming_data(sctp, data, len, ntohl(recv_info.rcv_ppid), recv_info.rcv_sid, flags);
  }
  free(data);  // we need to free the memory that usrsctp allocates
  return 0;
}
#endif

int sctp_create_association(Sctp* sctp, DtlsSrtp* dtls_srtp) {
  sctp->dtls_srtp = dtls_srtp;
  sctp->local_port = 5000;
  sctp->remote_port = 5000;
  sctp->tsn = 1234;
#if CONFIG_USE_USRSCTP
  int ret = -1;
  usrsctp_init(0, sctp_outgoing_data_cb, NULL);
  usrsctp_sysctl_set_sctp_ecn_enable(0);
  usrsctp_register_address(sctp);

  struct socket* sock = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP,
                                       sctp_incoming_data_cb, NULL, 0, sctp);

  if (!sock) {
    LOGE("usrsctp_socket failed");
    return -1;
  }

  do {
    if (usrsctp_set_non_blocking(sock, 1) < 0) {
      LOGE("usrsctp_set_non_blocking failed");
      break;
    }

    struct linger lopt;
    lopt.l_onoff = 1;
    lopt.l_linger = 0;
    usrsctp_setsockopt(sock, SOL_SOCKET, SO_LINGER, &lopt, sizeof(lopt));

#if 0
    struct sctp_paddrparams peer_param;
    memset(&peer_param, 0, sizeof peer_param);
    peer_param.spp_flags = SPP_PMTUD_DISABLE;
    peer_param.spp_pathmtu = 1200;
    usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &peer_param, sizeof peer_param);
#endif

    struct sctp_assoc_value av;
    av.assoc_id = SCTP_ALL_ASSOC;
    av.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ | SCTP_ENABLE_CHANGE_ASSOC_REQ;
    usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &av, sizeof(av));

    uint32_t nodelay = 1;
    usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_NODELAY, &nodelay, sizeof(nodelay));

    static uint16_t event_types[] = {
        SCTP_ASSOC_CHANGE,
        SCTP_PEER_ADDR_CHANGE,
        SCTP_REMOTE_ERROR,
        SCTP_SHUTDOWN_EVENT,
        SCTP_ADAPTATION_INDICATION,
        SCTP_SEND_FAILED_EVENT,
        SCTP_SENDER_DRY_EVENT,
        SCTP_STREAM_RESET_EVENT,
        SCTP_STREAM_CHANGE_EVENT};

    struct sctp_event event;
    memset(&event, 0, sizeof(event));
    event.se_assoc_id = SCTP_ALL_ASSOC;
    event.se_on = 1;
    for (int i = 0; i < sizeof(event_types) / sizeof(uint16_t); i++) {
      event.se_type = event_types[i];
      usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event));
    }

    struct sctp_initmsg init_msg;
    memset(&init_msg, 0, sizeof init_msg);
    init_msg.sinit_num_ostreams = 300;
    init_msg.sinit_max_instreams = 300;
    usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_INITMSG, &init_msg, sizeof init_msg);

    struct sockaddr_conn sconn;
    memset(&sconn, 0, sizeof(sconn));
    sconn.sconn_family = AF_CONN;
    sconn.sconn_port = htons(sctp->local_port);
    sconn.sconn_addr = (void*)sctp;
    ret = usrsctp_bind(sock, (struct sockaddr*)&sconn, sizeof(sconn));

    struct sockaddr_conn rconn;

    memset(&rconn, 0, sizeof(struct sockaddr_conn));
    rconn.sconn_family = AF_CONN;
    rconn.sconn_port = htons(sctp->remote_port);
    rconn.sconn_addr = (void*)sctp;
    ret = usrsctp_connect(sock, (struct sockaddr*)&rconn, sizeof(struct sockaddr_conn));

    if (ret < 0 && errno != EINPROGRESS) {
      LOGE("connect error");
      break;
    }

    ret = 0;

  } while (0);

  if (ret < 0) {
    sctp_destroy_association(sctp);
    return -1;
  }

  sctp->sock = sock;
#else
  // SpawnDev: fresh receive state per association (a reconnect must not inherit the last session's TSNs).
  sctp->rx_tsn_valid = 0;
  sctp->rx_gap_bits = 0;
  sctp->rx_frag_active = 0;
  sctp->rx_frag_len = 0;
  sctp_tx_reset(sctp);  // SpawnDev: fresh send window (starts at the initial TSN)

  // send SCTP_INIT
  int length = 0;
  SctpInitChunk* init_chunk;
  SctpHeader* header;
  SctpPacket* out_packet = (SctpPacket*)sctp->buf;
  header = &out_packet->header;
  init_chunk = (SctpInitChunk*)out_packet->chunks;

  header->source_port = htons(sctp->local_port);
  header->destination_port = htons(sctp->remote_port);
  header->verification_tag = 0x0;
  init_chunk->common.type = SCTP_INIT;
  init_chunk->common.flags = 0x00;
  init_chunk->common.length = htons(20 + 4);
  init_chunk->initiate_tag = htonl(0x12345678);
  init_chunk->a_rwnd = htonl(0x100000);
  init_chunk->number_of_outbound_streams = 0xffff;
  init_chunk->number_of_inbound_streams = 0xffff;
  init_chunk->initial_tsn = htonl(sctp->tsn);
  // SpawnDev: advertise Forward-TSN support (RFC 3758), so the peer accepts FORWARD-TSN for skipped video chunks.
  init_chunk->param[0].type = htons(SCTP_PARAM_FORWARD_TSN_SUPPORTED);
  init_chunk->param[0].length = htons(4);
  length = ntohs(init_chunk->common.length) + sizeof(SctpHeader);
  length = (4 * ((length + 3) / 4));
  header->checksum = sctp_get_checksum(sctp, sctp->buf, length);
  dtls_srtp_write(sctp->dtls_srtp, sctp->buf, length);
  sctp_hs_remember(sctp, 1, sctp->buf, length);  // SpawnDev: resent by sctp_tick until INIT-ACK
#endif

  return 0;
}

void sctp_destroy_association(Sctp* sctp) {
#if CONFIG_USE_USRSCTP
  if (sctp && sctp->sock) {
    usrsctp_shutdown(sctp->sock, SHUT_RDWR);
    usrsctp_close(sctp->sock);
    usrsctp_finish();
    sctp->sock = NULL;
  }
#else
  if (sctp && sctp->rx_frag) {
    free(sctp->rx_frag);  // SpawnDev: reassembly buffer
    sctp->rx_frag = NULL;
    sctp->rx_frag_active = 0;
  }
  if (sctp) {
    // SpawnDev: send window + retransmission store
    free(sctp->hs_pkt);
    sctp->hs_pkt = NULL;
    sctp->hs_state = 0;
    free(sctp->tx);
    free(sctp->tx_store);
    sctp->tx = NULL;
    sctp->tx_store = NULL;
    sctp->tx_valid = 0;
  }
#endif
}

int sctp_is_connected(Sctp* sctp) {
  return sctp->connected;
}

void sctp_onmessage(Sctp* sctp, void (*onmessage)(char* msg, size_t len, void* userdata, uint16_t sid)) {
  sctp->onmessage = onmessage;
}

void sctp_onopen(Sctp* sctp, void (*onopen)(void* userdata)) {
  sctp->onopen = onopen;
}

void sctp_onclose(Sctp* sctp, void (*onclose)(void* userdata)) {
  sctp->onclose = onclose;
}
