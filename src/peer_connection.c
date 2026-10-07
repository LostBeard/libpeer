#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "agent.h"
#include "buffer.h"
#include "config.h"
#include "dtls_srtp.h"
#include "peer_connection.h"
#include "ports.h"
#include "rtcp.h"
#include "rtp.h"
#include "sctp.h"
#include "sdp.h"

#define STATE_CHANGED(pc, curr_state)                                 \
  if (pc->oniceconnectionstatechange && pc->state != curr_state) {    \
    pc->oniceconnectionstatechange(curr_state, pc->config.user_data); \
    pc->state = curr_state;                                           \
  }

struct PeerConnection {
  PeerConfiguration config;
  PeerConnectionState state;
  Agent agent;
  DtlsSrtp dtls_srtp;
  Sctp sctp;

  Sdp local_sdp;
  Sdp remote_sdp;

  void (*onicecandidate)(char* sdp, void* user_data);
  void (*oniceconnectionstatechange)(PeerConnectionState state, void* user_data);
  void (*on_connected)(void* userdata);
  void (*on_receiver_packet_loss)(float fraction_loss, uint32_t total_loss, void* user_data);

  uint8_t temp_buf[CONFIG_MTU];
  uint8_t agent_buf[CONFIG_MTU];
  int agent_ret;
  int b_local_description_created;
  uint32_t dtls_start_ms;  // SpawnWear: ms when ICE reached CONNECTED, to delay the ANSWERER's ClientHello
  uint32_t hs_tx, hs_rx;   // SpawnDev: datagrams sent / received while the DTLS handshake runs (diagnostics)

  Buffer* audio_rb;
  Buffer* video_rb;
  Buffer* data_rb;

  RtpEncoder artp_encoder;
  RtpEncoder vrtp_encoder;
  RtpDecoder vrtp_decoder;
  RtpDecoder artp_decoder;

  uint32_t remote_assrc;
  uint32_t remote_vssrc;
};

static void peer_connection_outgoing_rtp_packet(uint8_t* data, size_t size, void* user_data) {
  PeerConnection* pc = (PeerConnection*)user_data;
  dtls_srtp_encrypt_rtp_packet(&pc->dtls_srtp, data, (int*)&size);
  agent_send(&pc->agent, data, size);
}

static int peer_connection_dtls_srtp_recv(void* ctx, unsigned char* buf, size_t len) {
  int ret = -1;
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  PeerConnection* pc = (PeerConnection*)dtls_srtp->user_data;

  if (pc->agent_ret > 0 && pc->agent_ret <= len) {
    memcpy(buf, pc->agent_buf, pc->agent_ret);
    return pc->agent_ret;
  }

  // SpawnWear (Phase 7b): NON-BLOCKING. Do ONE agent_recv (which also services incoming ICE/STUN
  // so the connection's keepalives keep flowing) and return WANT_READ if there's no DTLS data yet,
  // instead of spinning CONFIG_TLS_READ_TIMEOUT times - that spun the pump task (mutex held =>
  // froze the watch) and starved ICE (peer disconnected after ~8s during the DTLS handshake).
  ret = agent_recv(&pc->agent, buf, len);
  if (ret > 0) {
    if (pc->state == PEER_CONNECTION_CONNECTED) pc->hs_rx++;
    return ret;
  }
  return MBEDTLS_ERR_SSL_WANT_READ;
}

// SpawnWear (watch-answers-offers): f_recv_timeout for mbedtls. Identical ICE-aware read to
// peer_connection_dtls_srtp_recv, but returns MBEDTLS_ERR_SSL_TIMEOUT (not WANT_READ) when there's no
// DTLS data. TIMEOUT lets mbedtls' DTLS RETRANSMISSION fire: as the ANSWERER the watch sends its
// ClientHello before the peer's DTLS transport is ready (the peer logs "no DTLS transport available" and
// drops it), so the handshake hangs forever unless the watch RESENDS. With f_recv_timeout=NULL +
// WANT_READ, mbedtls never retransmitted. Still NON-BLOCKING (one agent_recv) so it never holds the pump
// mutex; mbedtls' static timer (set in dtls_srtp_do_handshake) governs the actual ~1s resend cadence
// regardless of how fast we return. Safe now the watch is always a DTLS CLIENT (ClientHello built first).
static int peer_connection_dtls_srtp_recv_timeout(void* ctx, unsigned char* buf, size_t len, uint32_t timeout) {
  (void)timeout;
  int ret = -1;
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  PeerConnection* pc = (PeerConnection*)dtls_srtp->user_data;

  if (pc->agent_ret > 0 && pc->agent_ret <= len) {
    memcpy(buf, pc->agent_buf, pc->agent_ret);
    return pc->agent_ret;
  }

  ret = agent_recv(&pc->agent, buf, len);
  if (ret > 0) {
    return ret;
  }
  return MBEDTLS_ERR_SSL_TIMEOUT;
}

static int peer_connection_dtls_srtp_send(void* ctx, const uint8_t* buf, size_t len) {
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  PeerConnection* pc = (PeerConnection*)dtls_srtp->user_data;

  // LOGD("send %.4x %.4x, %ld", *(uint16_t*)buf, *(uint16_t*)(buf + 2), len);
  if (pc->state == PEER_CONNECTION_CONNECTED) pc->hs_tx++;
  return agent_send(&pc->agent, buf, len);
}

static void peer_connection_incoming_rtcp(PeerConnection* pc, uint8_t* buf, size_t len) {
  RtcpHeader* rtcp_header;
  size_t pos = 0;

  while (pos < len) {
    rtcp_header = (RtcpHeader*)(buf + pos);

    switch (rtcp_header->type) {
      case RTCP_RR:
        LOGD("RTCP_PR");
        if (rtcp_header->rc > 0) {
// TODO: REMB, GCC ...etc
#if 0
          RtcpRr rtcp_rr = rtcp_parse_rr(buf);
          uint32_t fraction = ntohl(rtcp_rr.report_block[0].flcnpl) >> 24;
          uint32_t total = ntohl(rtcp_rr.report_block[0].flcnpl) & 0x00FFFFFF;
          if(pc->on_receiver_packet_loss && fraction > 0) {

            pc->on_receiver_packet_loss((float)fraction/256.0, total, pc->config.user_data);
          }
#endif
        }
        break;
      case RTCP_PSFB: {
        int fmt = rtcp_header->rc;
        LOGD("RTCP_PSFB %d", fmt);
        // PLI and FIR
        if ((fmt == 1 || fmt == 4) && pc->config.on_request_keyframe) {
          pc->config.on_request_keyframe(pc->config.user_data);
        }
      }
      default:
        break;
    }

    pos += 4 * ntohs(rtcp_header->length) + 4;
  }
}

const char* peer_connection_state_to_string(PeerConnectionState state) {
  switch (state) {
    case PEER_CONNECTION_NEW:
      return "new";
    case PEER_CONNECTION_CHECKING:
      return "checking";
    case PEER_CONNECTION_CONNECTED:
      return "connected";
    case PEER_CONNECTION_COMPLETED:
      return "completed";
    case PEER_CONNECTION_FAILED:
      return "failed";
    case PEER_CONNECTION_CLOSED:
      return "closed";
    case PEER_CONNECTION_DISCONNECTED:
      return "disconnected";
    default:
      return "unknown";
  }
}

PeerConnectionState peer_connection_get_state(PeerConnection* pc) {
  return pc->state;
}

void* peer_connection_get_sctp(PeerConnection* pc) {
  return &pc->sctp;
}

PeerConnection* peer_connection_create(PeerConfiguration* config) {
  PeerConnection* pc = calloc(1, sizeof(PeerConnection));
  if (!pc) {
    return NULL;
  }

  memcpy(&pc->config, config, sizeof(PeerConfiguration));

  // SpawnWear (2026-06-30): agent_create opens the UDP socket; if the lwIP pool/heap is exhausted it
  // FAILS. Upstream ignored the return, so the PC was built with a dead socket and announced offers
  // that could never ICE-connect (masking the real socket/heap leak as a mystery "no ICE" timeout).
  // Fail loudly instead so exhaustion surfaces as a create failure, not a silent dead connection.
  if (agent_create(&pc->agent) < 0) {
    LOGE("agent_create failed (socket pool/heap exhausted?)");
    free(pc);
    return NULL;
  }

  memset(&pc->sctp, 0, sizeof(pc->sctp));

  if (pc->config.datachannel) {
#if (CONFIG_DATA_BUFFER_SIZE) > 0
    LOGI("Datachannel allocates heap size: %d", CONFIG_DATA_BUFFER_SIZE);
    pc->data_rb = buffer_new(CONFIG_DATA_BUFFER_SIZE);
#endif
  }

  if (pc->config.audio_codec) {
#if (CONFIG_AUDIO_BUFFER_SIZE) > 0
    LOGI("Audio allocates heap size: %d", CONFIG_AUDIO_BUFFER_SIZE);
    pc->audio_rb = buffer_new(CONFIG_AUDIO_BUFFER_SIZE);
#endif

    rtp_encoder_init(&pc->artp_encoder, pc->config.audio_codec,
                     peer_connection_outgoing_rtp_packet, (void*)pc);

    rtp_decoder_init(&pc->artp_decoder, pc->config.audio_codec,
                     pc->config.onaudiotrack, pc->config.user_data);
  }

  if (pc->config.video_codec) {
#if (CONFIG_VIDEO_BUFFER_SIZE) > 0
    LOGI("Video allocates heap size: %d", CONFIG_VIDEO_BUFFER_SIZE);
    pc->video_rb = buffer_new(CONFIG_VIDEO_BUFFER_SIZE);
#endif
    rtp_encoder_init(&pc->vrtp_encoder, pc->config.video_codec,
                     peer_connection_outgoing_rtp_packet, (void*)pc);

    rtp_decoder_init(&pc->vrtp_decoder, pc->config.video_codec,
                     pc->config.onvideotrack, pc->config.user_data);
  }

  return pc;
}

void peer_connection_destroy(PeerConnection* pc) {
  if (pc) {
    sctp_destroy_association(&pc->sctp);
    dtls_srtp_deinit(&pc->dtls_srtp);
    agent_destroy(&pc->agent);
    buffer_free(pc->data_rb);
    buffer_free(pc->audio_rb);
    buffer_free(pc->video_rb);

    free(pc);
    pc = NULL;
  }
}

void peer_connection_close(PeerConnection* pc) {
  pc->state = PEER_CONNECTION_CLOSED;
}

int peer_connection_send_audio(PeerConnection* pc, const uint8_t* buf, size_t len) {
  if (pc->state != PEER_CONNECTION_COMPLETED) {
    // LOGE("dtls_srtp not connected");
    return -1;
  }
#if (CONFIG_AUDIO_BUFFER_SIZE) > 0
  return buffer_push_tail(pc->audio_rb, buf, len);
#else
  return rtp_encoder_encode(&pc->artp_encoder, buf, len);
#endif
}

int peer_connection_send_video(PeerConnection* pc, const uint8_t* buf, size_t len) {
  if (pc->state != PEER_CONNECTION_COMPLETED) {
    // LOGE("dtls_srtp not connected");
    return -1;
  }
#if (CONFIG_VIDEO_BUFFER_SIZE) > 0
  return buffer_push_tail(pc->video_rb, buf, len);
#else
  return rtp_encoder_encode(&pc->vrtp_encoder, data, bytes);
#endif
}

// SpawnWear (Phase 7b): RFC 8832 §6 - the DTLS SERVER must use ODD SCTP stream ids, the DTLS
// CLIENT even ones. libpeer historically hardcoded sid 0 (only correct when it is the client).
// The watch is the DTLS server (a=setup:passive), so its single data channel lives on sid 1;
// using sid 0 made SipSorcery/Chrome drop our DATA as "no channel found for stream 0".
static inline uint16_t peer_connection_default_dc_sid(PeerConnection* pc) {
  return pc->dtls_srtp.role == DTLS_SRTP_ROLE_SERVER ? 1 : 0;
}

int peer_connection_is_dtls_server(PeerConnection* pc) {
  // SpawnDev: lets callers pick RFC 8832 stream ids (DTLS server = odd, client = even) for extra channels.
  return pc->dtls_srtp.role == DTLS_SRTP_ROLE_SERVER ? 1 : 0;
}

int peer_connection_datachannel_send(PeerConnection* pc, char* message, size_t len) {
  return peer_connection_datachannel_send_sid(pc, message, len, peer_connection_default_dc_sid(pc));
}

int peer_connection_datachannel_send_sid_direct(PeerConnection* pc, char* message, size_t len, uint16_t sid) {
  // SpawnDev: sends immediately, bypassing the data ring (no copy). Call ONLY from the thread that runs
  // peer_connection_loop (or with the same lock held), since SCTP/DTLS state is not thread safe.
  if (!sctp_is_connected(&pc->sctp))
    return -1;
  if (pc->config.datachannel == DATA_CHANNEL_STRING)
    return sctp_outgoing_data(&pc->sctp, message, len, PPID_STRING, sid);
  return sctp_outgoing_data(&pc->sctp, message, len, PPID_BINARY, sid);
}

int peer_connection_datachannel_send_sid(PeerConnection* pc, char* message, size_t len, uint16_t sid) {
  if (!sctp_is_connected(&pc->sctp)) {
    LOGE("sctp not connected");
    return -1;
  }

#if (CONFIG_DATA_BUFFER_SIZE) > 0
  // SpawnDev: keep the stream id with the message. The ring used to hold only the payload and the drain sent
  // everything on the default stream, so a second data channel could never receive anything.
  uint8_t* entry = (uint8_t*)malloc(len + 2);
  if (!entry)
    return -1;
  entry[0] = (uint8_t)(sid & 0xff);
  entry[1] = (uint8_t)(sid >> 8);
  memcpy(entry + 2, message, len);
  int pushed = buffer_push_tail(pc->data_rb, entry, (int)len + 2);
  free(entry);
  return pushed;
#else
  if (pc->config.datachannel == DATA_CHANNEL_STRING)
    return sctp_outgoing_data(&pc->sctp, message, len, PPID_STRING, sid);
  else
    return sctp_outgoing_data(&pc->sctp, message, len, PPID_BINARY, sid);
#endif
}

int peer_connection_create_datachannel(PeerConnection* pc, DecpChannelType channel_type, uint16_t priority, uint32_t reliability_parameter, char* label, char* protocol) {
  // SpawnWear (Phase 7b): pick the DCEP stream-id parity from our DTLS role (RFC 8832 §6) -
  // server=odd, client=even - instead of always 0. See peer_connection_default_dc_sid above.
  return peer_connection_create_datachannel_sid(pc, channel_type, priority, reliability_parameter, label, protocol, peer_connection_default_dc_sid(pc));
}

int peer_connection_create_datachannel_sid(PeerConnection* pc, DecpChannelType channel_type, uint16_t priority, uint32_t reliability_parameter, char* label, char* protocol, uint16_t sid) {
  int rtrn = -1;

  if (!sctp_is_connected(&pc->sctp)) {
    LOGE("sctp not connected");
    return rtrn;
  }

  //  0                   1                   2                   3
  //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |  Message Type |  Channel Type |            Priority           |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                    Reliability Parameter                      |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |         Label Length          |       Protocol Length         |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                                                               |
  // |                             Label                             |
  // |                                                               |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                                                               |
  // |                            Protocol                           |
  // |                                                               |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  int msg_size = 12 + strlen(label) + strlen(protocol);
  uint16_t priority_big_endian = htons(priority);
  uint32_t reliability_big_endian = ntohl(reliability_parameter);
  uint16_t label_length = htons(strlen(label));
  uint16_t protocol_length = htons(strlen(protocol));
  char* msg = calloc(1, msg_size);

  msg[0] = DATA_CHANNEL_OPEN;
  // SpawnDev: the channel type was never written, so every channel opened as reliable + ordered (RFC 8832).
  msg[1] = (char)channel_type;
  memcpy(msg + 2, &priority_big_endian, sizeof(uint16_t));
  memcpy(msg + 4, &reliability_big_endian, sizeof(uint32_t));
  memcpy(msg + 8, &label_length, sizeof(uint16_t));
  memcpy(msg + 10, &protocol_length, sizeof(uint16_t));
  memcpy(msg + 12, label, strlen(label));
  memcpy(msg + 12 + strlen(label), protocol, strlen(protocol));

  rtrn = sctp_outgoing_data(&pc->sctp, msg, msg_size, PPID_CONTROL, sid);
  free(msg);
  // SpawnDev: remember our own channel's label -> sid too, so peer_connection_lookup_sid finds it.
  sctp_add_stream_mapping(&pc->sctp, label, sid);
  // SpawnDev: a partial-reliability channel with 0 retransmits (or a timed one) is never retransmitted.
  int partial = (channel_type & 0x7F) != DATA_CHANNEL_RELIABLE;
  sctp_set_stream_unreliable(&pc->sctp, sid, partial && (reliability_parameter == 0 || (channel_type & 0x7F) == DATA_CHANNEL_PARTIAL_RELIABLE_TIMED));
  return rtrn;
}

static char* peer_connection_dtls_role_setup_value(DtlsSrtpRole d) {
  return d == DTLS_SRTP_ROLE_SERVER ? "a=setup:passive" : "a=setup:active";
}

static void peer_connection_state_new(PeerConnection* pc, DtlsSrtpRole role, int isOfferer) {
  char* description = (char*)pc->temp_buf;

  memset(pc->temp_buf, 0, sizeof(pc->temp_buf));

  dtls_srtp_reset_session(&pc->dtls_srtp);
  dtls_srtp_init(&pc->dtls_srtp, role, pc);
  pc->dtls_srtp.udp_recv = peer_connection_dtls_srtp_recv;
  pc->dtls_srtp.udp_recv_timeout = peer_connection_dtls_srtp_recv_timeout;
  pc->dtls_srtp.udp_send = peer_connection_dtls_srtp_send;

  pc->sctp.connected = 0;

  if (isOfferer) {
    agent_clear_candidates(&pc->agent);
    pc->agent.mode = AGENT_MODE_CONTROLLING;
  } else {
    pc->agent.mode = AGENT_MODE_CONTROLLED;
  }

  agent_gather_candidate(&pc->agent, NULL, NULL, NULL);  // host address
  for (int i = 0; i < sizeof(pc->config.ice_servers) / sizeof(pc->config.ice_servers[0]); ++i) {
    if (pc->config.ice_servers[i].urls) {
      LOGI("ice server: %s", pc->config.ice_servers[i].urls);
      agent_gather_candidate(&pc->agent, pc->config.ice_servers[i].urls, pc->config.ice_servers[i].username, pc->config.ice_servers[i].credential);
    }
  }

  agent_get_local_description(&pc->agent, description, sizeof(pc->temp_buf));

  memset(&pc->local_sdp, 0, sizeof(pc->local_sdp));
  // TODO: check if we have video or audio codecs
  sdp_create(&pc->local_sdp,
             pc->config.video_codec != CODEC_NONE,
             pc->config.audio_codec != CODEC_NONE,
             pc->config.datachannel);

  if (pc->config.video_codec == CODEC_H264) {
    sdp_append_h264(&pc->local_sdp);
    sdp_append(&pc->local_sdp, "a=fingerprint:sha-256 %s", pc->dtls_srtp.local_fingerprint);
    sdp_append(&pc->local_sdp, peer_connection_dtls_role_setup_value(role));
    sdp_append(&pc->local_sdp, description);
  }

  switch (pc->config.audio_codec) {
    case CODEC_PCMA:

      sdp_append_pcma(&pc->local_sdp);
      sdp_append(&pc->local_sdp, "a=fingerprint:sha-256 %s", pc->dtls_srtp.local_fingerprint);
      sdp_append(&pc->local_sdp, peer_connection_dtls_role_setup_value(role));
      sdp_append(&pc->local_sdp, description);
      break;

    case CODEC_PCMU:

      sdp_append_pcmu(&pc->local_sdp);
      sdp_append(&pc->local_sdp, "a=fingerprint:sha-256 %s", pc->dtls_srtp.local_fingerprint);
      sdp_append(&pc->local_sdp, peer_connection_dtls_role_setup_value(role));
      sdp_append(&pc->local_sdp, description);
      break;

    case CODEC_OPUS:
      sdp_append_opus(&pc->local_sdp);
      sdp_append(&pc->local_sdp, "a=fingerprint:sha-256 %s", pc->dtls_srtp.local_fingerprint);
      sdp_append(&pc->local_sdp, peer_connection_dtls_role_setup_value(role));
      sdp_append(&pc->local_sdp, description);

    default:
      break;
  }

  if (pc->config.datachannel) {
    sdp_append_datachannel(&pc->local_sdp);
    sdp_append(&pc->local_sdp, "a=fingerprint:sha-256 %s", pc->dtls_srtp.local_fingerprint);
    sdp_append(&pc->local_sdp, peer_connection_dtls_role_setup_value(role));
    sdp_append(&pc->local_sdp, description);
  }

  pc->b_local_description_created = 1;

  if (pc->onicecandidate) {
    pc->onicecandidate(pc->local_sdp.content, pc->config.user_data);
  }
}

int peer_connection_loop(PeerConnection* pc) {
  int bytes;
  uint8_t* data = NULL;
  uint32_t ssrc = 0;
  memset(pc->agent_buf, 0, sizeof(pc->agent_buf));
  pc->agent_ret = -1;

  switch (pc->state) {
    case PEER_CONNECTION_NEW:

      if (!pc->b_local_description_created) {
        // SpawnWear (Phase 7c): the watch (offerer) is the DTLS CLIENT (a=setup:active), not server.
        // Browsers (Chrome/Firefox) send a large DTLS ClientHello that exceeds the DTLS MTU and gets
        // FRAGMENTED across handshake records; mbedTLS's SERVER refuses to reassemble the initial
        // ClientHello (ssl_tls12_server.c: "ClientHello fragmentation not supported" ->
        // FEATURE_UNAVAILABLE). As the CLIENT, the watch sends its own SMALL ClientHello and reads the
        // peer's flight through mbedTLS's normal read_record path, which DOES reassemble fragments.
        // The answerer (browser/SipSorcery) becomes the DTLS server (setup:passive). Our role-based
        // SCTP stream-id (peer_connection_default_dc_sid) auto-switches the data channel to even
        // stream 0, correct for the DTLS client per RFC 8832 §6.
        peer_connection_state_new(pc, DTLS_SRTP_ROLE_CLIENT, 1);
      }
      break;

    case PEER_CONNECTION_CHECKING:
      if (agent_select_candidate_pair(&pc->agent) < 0) {
        STATE_CHANGED(pc, PEER_CONNECTION_FAILED);
      } else if (agent_connectivity_check(&pc->agent) == 0) {
        pc->dtls_start_ms = ports_get_epoch_time();  // SpawnWear: mark ICE-connected for the answerer DTLS delay
        STATE_CHANGED(pc, PEER_CONNECTION_CONNECTED);
      }
      break;

    case PEER_CONNECTION_CONNECTED: {
      // SpawnWear (watch-answers-offers): DELAY the ANSWERER's DTLS start. As the answerer (ICE CONTROLLED)
      // the watch reaches CONNECTED ~3s BEFORE the peer (offerer) finishes ICE + brings up its DTLS server,
      // so an immediately-sent ClientHello is DROPPED ("no DTLS transport available") and - with no working
      // non-blocking retransmission - the handshake hangs. Holding off the ClientHello until the peer is up
      // sidesteps that. The OFFERER (CONTROLLING) never delays: its peer (answerer) has DTLS ready first, so
      // its ClientHello lands immediately (the proven offer path). The managed StateCompleted wait (15s)
      // tolerates the hold.
      if (pc->agent.mode == AGENT_MODE_CONTROLLED &&
          (ports_get_epoch_time() - pc->dtls_start_ms) < 3500) {
        // Keep ICE alive during the hold (respond to the peer's binding requests); in CONNECTED the only
        // place STUN is serviced is the DTLS recv, which we're deferring - so pump the agent directly here.
        // Don't start DTLS yet (no ClientHello until the peer's DTLS server is up).
        agent_recv(&pc->agent, pc->agent_buf, sizeof(pc->agent_buf));
        break;
      }
      // SpawnWear (Phase 7b): the handshake is now NON-BLOCKING. 0 = done; WANT_READ/WANT_WRITE =
      // still in progress (retry next loop); anything else = a FATAL DTLS error -> go to FAILED so
      // we stop re-driving a dead handshake (which otherwise spun this loop forever).
      int hs = dtls_srtp_handshake(&pc->dtls_srtp, NULL);
      if (hs == 0) {
        LOGD("DTLS-SRTP handshake done");

        if (pc->config.datachannel) {
          LOGI("SCTP create socket");
          sctp_create_association(&pc->sctp, &pc->dtls_srtp);
          pc->sctp.userdata = pc->config.user_data;
        }

        STATE_CHANGED(pc, PEER_CONNECTION_COMPLETED);
      } else if (hs != MBEDTLS_ERR_SSL_WANT_READ && hs != MBEDTLS_ERR_SSL_WANT_WRITE && hs != MBEDTLS_ERR_SSL_TIMEOUT) {
        // SpawnWear (watch-answers-offers): MBEDTLS_ERR_SSL_TIMEOUT is NOT fatal - it means a DTLS read
        // window elapsed with no data (our f_recv_timeout returns it). Keep retrying (stay CONNECTED) so
        // mbedtls' retransmission timer fires and RESENDS the flight (the answerer's ClientHello, which
        // the peer dropped because its DTLS transport wasn't up yet). The managed StateCompleted wait
        // bounds the overall retry window, so a genuinely dead handshake still gives up there.
        STATE_CHANGED(pc, PEER_CONNECTION_FAILED);
      }
      break;
    }
    case PEER_CONNECTION_COMPLETED:
      pc->agent.nonblocking = 1;

#if (CONFIG_VIDEO_BUFFER_SIZE) > 0
      data = buffer_peak_head(pc->video_rb, &bytes);
      if (data) {
        rtp_encoder_encode(&pc->vrtp_encoder, data, bytes);
        buffer_pop_head(pc->video_rb);
      }
#endif

#if (CONFIG_AUDIO_BUFFER_SIZE) > 0
      data = buffer_peak_head(pc->audio_rb, &bytes);
      if (data) {
        rtp_encoder_encode(&pc->artp_encoder, data, bytes);
        buffer_pop_head(pc->audio_rb);
      }
#endif

#if (CONFIG_DATA_BUFFER_SIZE) > 0
      data = buffer_peak_head(pc->data_rb, &bytes);
      if (data && bytes >= 2) {
        // SpawnDev: entries are [u16 sid][payload] (see peer_connection_datachannel_send_sid).
        uint16_t entry_sid = (uint16_t)(data[0] | (data[1] << 8));
        if (pc->config.datachannel == DATA_CHANNEL_STRING)
          sctp_outgoing_data(&pc->sctp, (char*)data + 2, bytes - 2, PPID_STRING, entry_sid);
        else
          sctp_outgoing_data(&pc->sctp, (char*)data + 2, bytes - 2, PPID_BINARY, entry_sid);
        buffer_pop_head(pc->data_rb);
      } else if (data) {
        buffer_pop_head(pc->data_rb);  // malformed entry
      }
#endif

      // SpawnDev: read every waiting datagram (bounded), not one per pass. The pump sleeps a FreeRTOS tick (10 ms)
      // between passes, so one read per pass capped intake near 100 packets/s; a peer that SACKs every packet
      // (SipSorcery) during video filled that, its ICE consent checks waited behind the SACKs, and after 8 s
      // unanswered it declared the connection dead.
      for (int rx_burst = 0; rx_burst < 16; rx_burst++) {
        if ((pc->agent_ret = agent_recv(&pc->agent, pc->agent_buf, sizeof(pc->agent_buf))) > 0) {
          LOGD("agent_recv %d", pc->agent_ret);

          if (rtcp_probe(pc->agent_buf, pc->agent_ret)) {
            LOGD("Got RTCP packet");
            dtls_srtp_decrypt_rtcp_packet(&pc->dtls_srtp, pc->agent_buf, &pc->agent_ret);
            peer_connection_incoming_rtcp(pc, pc->agent_buf, pc->agent_ret);

          } else if (dtls_srtp_probe(pc->agent_buf)) {
            int ret = dtls_srtp_read(&pc->dtls_srtp, pc->temp_buf, sizeof(pc->temp_buf));
            LOGD("Got DTLS data %d", ret);

            if (ret > 0) {
              sctp_incoming_data(&pc->sctp, (char*)pc->temp_buf, ret);
            }

          } else if (rtp_packet_validate(pc->agent_buf, pc->agent_ret)) {
            LOGD("Got RTP packet");

            dtls_srtp_decrypt_rtp_packet(&pc->dtls_srtp, pc->agent_buf, &pc->agent_ret);

            ssrc = rtp_get_ssrc(pc->agent_buf);
            if (ssrc == pc->remote_assrc) {
              rtp_decoder_decode(&pc->artp_decoder, pc->agent_buf, pc->agent_ret);
            } else if (ssrc == pc->remote_vssrc) {
              rtp_decoder_decode(&pc->vrtp_decoder, pc->agent_buf, pc->agent_ret);
            }

          } else {
            LOGW("Unknown data");
          }
        }
        if (pc->agent.last_rx_bytes <= 0) {
          break;  // nothing more waiting
        }
      }

      sctp_tick(&pc->sctp);  // SpawnDev: retransmissions + FORWARD-TSN

      if (CONFIG_KEEPALIVE_TIMEOUT > 0 && (ports_get_epoch_time() - pc->agent.binding_request_time) > CONFIG_KEEPALIVE_TIMEOUT) {
        LOGI("binding request timeout");
        STATE_CHANGED(pc, PEER_CONNECTION_CLOSED);
      }

      break;
    case PEER_CONNECTION_FAILED:
      break;
    case PEER_CONNECTION_DISCONNECTED:
      break;
    case PEER_CONNECTION_CLOSED:
      break;
    default:
      break;
  }

  return 0;
}

void peer_connection_set_remote_description(PeerConnection* pc, const char* sdp_text) {
  char* start = (char*)sdp_text;
  char* line = NULL;
  char buf[256];
  char* val_start = NULL;
  uint32_t* ssrc = NULL;
  // SpawnWear (watch-answers-offers): the answerer defaults to DTLS CLIENT, not SERVER. A browser offers
  // "a=setup:actpass" (RFC 5763); the answerer then picks active=CLIENT so the watch sends its own SMALL
  // ClientHello (mbedTLS as SERVER can't reassemble a browser's FRAGMENTED ClientHello - the wall that
  // forced the watch offerer-only). Only an explicit "a=setup:active" offer makes us SERVER (below). Net:
  // the watch is ALWAYS the DTLS client. This is a NO-OP in the offerer path (b_local_description_created
  // is already true there, so the role-set below is skipped); it only fires when the watch ANSWERS.
  DtlsSrtpRole role = DTLS_SRTP_ROLE_CLIENT;
  int is_update = 0;
  Agent* agent = &pc->agent;

  while ((line = strstr(start, "\r\n"))) {
    line = strstr(start, "\r\n");
    strncpy(buf, start, line - start);
    buf[line - start] = '\0';

    // Offerer explicitly active -> the answerer MUST be passive (DTLS server). "a=setup:actpass" and
    // "a=setup:passive" both leave us CLIENT (the default above) - what browsers/SipSorcery send.
    // ("a=setup:active" is NOT a substring of "a=setup:actpass", so actpass stays CLIENT.)
    if (strstr(buf, "a=setup:active")) {
      role = DTLS_SRTP_ROLE_SERVER;
    }

    if (strstr(buf, "a=fingerprint")) {
      strncpy(pc->dtls_srtp.remote_fingerprint, buf + 22, DTLS_SRTP_FINGERPRINT_LENGTH);
    }

    if (strstr(buf, "a=ice-ufrag") &&
        strlen(agent->remote_ufrag) != 0 &&
        (strncmp(buf + strlen("a=ice-ufrag:"), agent->remote_ufrag, strlen(agent->remote_ufrag)) == 0)) {
      is_update = 1;
    }

    if (strstr(buf, "m=video")) {
      ssrc = &pc->remote_vssrc;
    } else if (strstr(buf, "m=audio")) {
      ssrc = &pc->remote_assrc;
    }

    if ((val_start = strstr(buf, "a=ssrc:")) && ssrc) {
      *ssrc = strtoul(val_start + 7, NULL, 10);
      LOGD("SSRC: %" PRIu32, *ssrc);
    }

    start = line + 2;
  }

  if (is_update) {
    return;
  }

  if (!pc->b_local_description_created) {
    peer_connection_state_new(pc, role, 0);
  }

  agent_set_remote_description(&pc->agent, (char*)sdp_text);
  STATE_CHANGED(pc, PEER_CONNECTION_CHECKING);
}

void peer_connection_create_offer(PeerConnection* pc) {
  STATE_CHANGED(pc, PEER_CONNECTION_NEW);
  pc->b_local_description_created = 0;
}

int peer_connection_send_rtcp_pil(PeerConnection* pc, uint32_t ssrc) {
  int ret = -1;
  uint8_t plibuf[128];
  rtcp_get_pli(plibuf, 12, ssrc);

  // TODO: encrypt rtcp packet
  // guint size = 12;
  // dtls_transport_encrypt_rctp_packet(pc->dtls_transport, plibuf, &size);
  // ret = nice_agent_send(pc->nice_agent, pc->stream_id, pc->component_id, size, (gchar*)plibuf);

  return ret;
}

// callbacks
void peer_connection_on_connected(PeerConnection* pc, void (*on_connected)(void* userdata)) {
  pc->on_connected = on_connected;
}

void peer_connection_on_receiver_packet_loss(PeerConnection* pc,
                                             void (*on_receiver_packet_loss)(float fraction_loss, uint32_t total_loss, void* userdata)) {
  pc->on_receiver_packet_loss = on_receiver_packet_loss;
}

void peer_connection_onicecandidate(PeerConnection* pc, void (*onicecandidate)(char* sdp_text, void* userdata)) {
  pc->onicecandidate = onicecandidate;
}

void peer_connection_oniceconnectionstatechange(PeerConnection* pc,
                                                void (*oniceconnectionstatechange)(PeerConnectionState state, void* userdata)) {
  pc->oniceconnectionstatechange = oniceconnectionstatechange;
}

void peer_connection_ondatachannel(PeerConnection* pc,
                                   void (*onmessage)(char* msg, size_t len, void* userdata, uint16_t sid),
                                   void (*onopen)(void* userdata),
                                   void (*onclose)(void* userdata)) {
  if (pc) {
    sctp_onopen(&pc->sctp, onopen);
    sctp_onclose(&pc->sctp, onclose);
    sctp_onmessage(&pc->sctp, onmessage);
  }
}

int peer_connection_lookup_sid(PeerConnection* pc, const char* label, uint16_t* sid) {
  for (int i = 0; i < pc->sctp.stream_count; i++) {
    if (strncmp(pc->sctp.stream_table[i].label, label, sizeof(pc->sctp.stream_table[i].label)) == 0) {
      *sid = pc->sctp.stream_table[i].sid;
      return 0;
    }
  }
  return -1;  // Not found
}

char* peer_connection_lookup_sid_label(PeerConnection* pc, uint16_t sid) {
  for (int i = 0; i < pc->sctp.stream_count; i++) {
    if (pc->sctp.stream_table[i].sid == sid) {
      return pc->sctp.stream_table[i].label;
    }
  }
  return NULL;  // Not found
}

int peer_connection_add_ice_candidate(PeerConnection* pc, char* candidate) {
  Agent* agent = &pc->agent;
  if (ice_candidate_from_description(&agent->remote_candidates[agent->remote_candidates_count], candidate, candidate + strlen(candidate)) != 0) {
    return -1;
  }

  agent->remote_candidates_count++;
  return 0;
}

// SpawnDev: SCTP send-side counters. 0 retransmits, 1 chunks abandoned, 2 FORWARD-TSN sent, 3 peer supports
// FORWARD-TSN, 4 reliable chunks sent without a retransmission copy, 5 datagrams dropped by the loss test.
int peer_connection_get_sctp_stat(PeerConnection* pc, int which) {
  if (!pc) return -1;
  switch (which) {
    case 0: return (int)pc->sctp.stat_retransmits;
    case 1: return (int)pc->sctp.stat_abandoned;
    case 2: return (int)pc->sctp.stat_forward_tsn;
    case 3: return pc->sctp.peer_forward_tsn;
    case 4: return (int)pc->sctp.stat_unprotected;
    case 5: return (int)pc->sctp.test_dropped;
  }
  return -1;
}

// SpawnDev: ICE diagnostics. 0 peer-reflexive candidates learned, 1 type of the selected pair's remote candidate
// (IceCandidateType, -1 before one is selected), 2 its IPv4 address (network order), 3 candidate pairs, 4 local
// candidates.
int peer_connection_get_ice_stat(PeerConnection* pc, int which) {
  if (!pc) return -1;
  switch (which) {
    case 0: return pc->agent.prflx_learned;
    case 1: return pc->agent.selected_pair ? (int)pc->agent.selected_pair->remote->type : -1;
    case 2: return pc->agent.selected_pair ? (int)pc->agent.selected_pair->remote->addr.sin.sin_addr.s_addr : 0;
    case 3: return pc->agent.candidate_pairs_num;
    case 4: return pc->agent.local_candidates_count;
    case 5: return (int)pc->hs_tx;
    case 6: return (int)pc->hs_rx;
    case 7: return (int)pc->dtls_srtp.ssl.MBEDTLS_PRIVATE(state);
    case 8: return (int)pc->sctp.stat_hs_retransmits;
    case 9: return mbedtls_ssl_get_ciphersuite_id_from_ssl(&pc->dtls_srtp.ssl);
  }
  return -1;
}

// SpawnDev: test hook. Drops this share (per mille) of outgoing DATA datagrams before they leave, to prove the
// retransmission and FORWARD-TSN paths on a real link. 0 = off.
void peer_connection_set_test_loss(PeerConnection* pc, int permille) {
  if (pc) pc->sctp.test_drop_permille = permille < 0 ? 0 : (permille > 1000 ? 1000 : (uint32_t)permille);
}
