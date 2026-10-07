#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "address.h"
#include "config.h"
#include "dtls_srtp.h"
#if CONFIG_MBEDTLS_DEBUG
#include "mbedtls/debug.h"
#endif
#define MBEDTLS_ALLOW_PRIVATE_ACCESS  // SpawnWear 7b: read ssl.state to name the failing handshake step
#include "mbedtls/sha256.h"
#include "mbedtls/ssl.h"
#include "ports.h"
#include "socket.h"
#include "utils.h"

// SpawnDev: time spent in application-data writes (encrypt + UDP send), to find where video send time goes.
#ifdef ESP_PLATFORM
#include "esp_timer.h"
#define SD_NOW_US() esp_timer_get_time()
#else
#define SD_NOW_US() 0
#endif
volatile uint32_t g_dtls_write_us = 0;
volatile uint32_t g_dtls_writes = 0;


int dtls_srtp_udp_send(void* ctx, const uint8_t* buf, size_t len) {
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  UdpSocket* udp_socket = (UdpSocket*)dtls_srtp->user_data;

  int ret = udp_socket_sendto(udp_socket, dtls_srtp->remote_addr, buf, len);

  LOGD("dtls_srtp_udp_send (%d)", ret);

  return ret;
}

#include "esp_attr.h"
// SpawnWear (Phase 7b) DTLS crash localization: a checkpoint in RTC noinit memory that SURVIVES
// the soft-reset reboot, so we can read where the handshake died via the interop GetState(-1).
// 1=handshake entered, 2=key derivation (SRTP) entered, 4=handshake fully returned (DTLS ok).
// Remove once the crash is root-caused.
RTC_NOINIT_ATTR volatile uint32_t g_sw_dtls_cp;

int dtls_srtp_udp_recv(void* ctx, uint8_t* buf, size_t len) {
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  UdpSocket* udp_socket = (UdpSocket*)dtls_srtp->user_data;

  int ret;
  // SpawnWear (Phase 7b): the original loop spun FOREVER waiting for DTLS data, which froze the
  // watch (the caller holds a mutex across peer_connection_loop). Bound it so the loop yields.
  int spins = 0;

  while ((ret = udp_socket_recvfrom(udp_socket, &udp_socket->bind_addr, buf, len)) <= 0) {
    ports_sleep_ms(1);
    if (++spins >= 2000) {  // ~2s safety cap
      return MBEDTLS_ERR_SSL_WANT_READ;  // SpawnWear: WANT_READ (poll), NOT TIMEOUT - TIMEOUT makes
                                         // mbedtls retransmit a not-yet-built flight (NULL deref crash)
    }
  }

  LOGD("dtls_srtp_udp_recv (%d)", ret);

  return ret;
}

// SpawnWear (Phase 7b): a timeout-aware recv for mbedtls' DTLS BIO. The DTLS retransmission timer
// is configured (mbedtls_ssl_set_timer_cb) but libpeer passed f_recv_timeout=NULL, so mbedtls
// could never time out to retransmit a lost flight - the handshake would hang forever. Wiring
// this as f_recv_timeout lets mbedtls drive retransmission and bounds each blocking wait.
int dtls_srtp_udp_recv_timeout(void* ctx, uint8_t* buf, size_t len, uint32_t timeout) {
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  UdpSocket* udp_socket = (UdpSocket*)dtls_srtp->user_data;

  int ret;
  uint32_t waited = 0;
  if (timeout == 0) {
    timeout = 1000;
  }

  while ((ret = udp_socket_recvfrom(udp_socket, &udp_socket->bind_addr, buf, len)) <= 0) {
    ports_sleep_ms(5);
    waited += 5;
    if (waited >= timeout) {
      return MBEDTLS_ERR_SSL_WANT_READ;  // SpawnWear: WANT_READ (poll), NOT TIMEOUT - TIMEOUT makes
                                         // mbedtls retransmit a not-yet-built flight (NULL deref crash)
    }
  }

  return ret;
}

static void dtls_srtp_x509_digest(const mbedtls_x509_crt* crt, char* buf) {
  int i;
  unsigned char digest[32];

  mbedtls_sha256_context sha256_ctx;
  mbedtls_sha256_init(&sha256_ctx);
  mbedtls_sha256_starts(&sha256_ctx, 0);
  mbedtls_sha256_update(&sha256_ctx, crt->raw.p, crt->raw.len);
  mbedtls_sha256_finish(&sha256_ctx, (unsigned char*)digest);
  mbedtls_sha256_free(&sha256_ctx);

  for (i = 0; i < 32; i++) {
    snprintf(buf, 4, "%.2X:", digest[i]);
    buf += 3;
  }

  *(--buf) = '\0';
}

// Do not verify CA
// SpawnDev: nor the validity dates. A WebRTC peer is identified by the certificate FINGERPRINT from the SDP (checked
// after the handshake), not by a chain or dates, and a device with no clock source has none to check them against:
// a MiniRover car in play mode (its own WiFi, no internet, so no SNTP) has a clock near 1970 and rejected a desktop
// peer's fresh certificate as not yet valid (MBEDTLS_X509_BADCERT_FUTURE -> alert certificate_unknown, measured).
static int dtls_srtp_cert_verify(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
  *flags &= ~(MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCERT_CN_MISMATCH | MBEDTLS_X509_BADCERT_BAD_KEY |
              MBEDTLS_X509_BADCERT_FUTURE | MBEDTLS_X509_BADCERT_EXPIRED);
  return 0;
}

static int dtls_srtp_selfsign_cert(DtlsSrtp* dtls_srtp) {
  int ret;

  mbedtls_x509write_cert crt;

  unsigned char* cert_buf = NULL;
#if CONFIG_MBEDTLS_2_X
  mbedtls_mpi serial;
#else
  const char* serial = "peer";
#endif
  const char* pers = "dtls_srtp";

  cert_buf = (unsigned char*)malloc(RSA_KEY_LENGTH * 2);
  if (cert_buf == NULL) {
    LOGE("malloc failed");
    return -1;
  }

  mbedtls_ctr_drbg_seed(&dtls_srtp->ctr_drbg, mbedtls_entropy_func, &dtls_srtp->entropy, (const unsigned char*)pers, strlen(pers));

#if CONFIG_DTLS_USE_ECDSA
  mbedtls_pk_setup(&dtls_srtp->pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
  mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(dtls_srtp->pkey), mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);
#else
  mbedtls_pk_setup(&dtls_srtp->pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  mbedtls_rsa_gen_key(mbedtls_pk_rsa(dtls_srtp->pkey), mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg, RSA_KEY_LENGTH, 65537);
#endif

  mbedtls_x509write_crt_init(&crt);

  mbedtls_x509write_crt_set_subject_key(&crt, &dtls_srtp->pkey);

  mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);

  mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

  mbedtls_x509write_crt_set_subject_key(&crt, &dtls_srtp->pkey);

  mbedtls_x509write_crt_set_issuer_key(&crt, &dtls_srtp->pkey);

  mbedtls_x509write_crt_set_subject_name(&crt, "CN=dtls_srtp");

  mbedtls_x509write_crt_set_issuer_name(&crt, "CN=dtls_srtp");

#if CONFIG_MBEDTLS_2_X
  mbedtls_mpi_init(&serial);
  mbedtls_mpi_fill_random(&serial, 16, mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);
  ret = mbedtls_x509write_crt_set_serial(&crt, &serial);
  if (ret < 0) {
    LOGE("mbedtls_x509write_crt_set_serial failed -0x%.4x", (unsigned int)-ret);
  }
#else
  mbedtls_x509write_crt_set_serial_raw(&crt, (unsigned char*)serial, strlen(serial));
#endif

  // SpawnDev: was valid until 2028-01-01 only; a peer that checks dates would refuse every device from then on.
  // The device's clock may be unset (no SNTP offline), so notBefore stays in the past.
  mbedtls_x509write_crt_set_validity(&crt, "20180101000000", "20991231235959");

  ret = mbedtls_x509write_crt_pem(&crt, cert_buf, 2 * RSA_KEY_LENGTH, mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);

  if (ret < 0) {
    LOGE("mbedtls_x509write_crt_pem failed -0x%.4x", (unsigned int)-ret);
  }

  mbedtls_x509_crt_parse(&dtls_srtp->cert, cert_buf, 2 * RSA_KEY_LENGTH);

  mbedtls_x509write_crt_free(&crt);

  free(cert_buf);

  return ret;
}

#if CONFIG_MBEDTLS_DEBUG
static void dtls_srtp_debug(void* ctx, int level, const char* file, int line, const char* str) {
  LOGD("%s:%04d: %s", file, line, str);
  // SpawnWear (Phase 7b) diag: encode the reason for an important (level<=1) mbedtls message into
  // the RTC checkpoint, read via GetState(-1) / /webrtc-checkpoint as 0x2000X. Remove once stable.
  if (level <= 1 && str != NULL) {
    if (strstr(str, "ciphersuite")) g_sw_dtls_cp = 0x20001;
    else if (strstr(str, "curve")) g_sw_dtls_cp = 0x20002;
    else if (strstr(str, "version")) g_sw_dtls_cp = 0x20003;
    else if (strstr(str, "ignature") || strstr(str, "sig_alg") || strstr(str, "sig alg")) g_sw_dtls_cp = 0x20004;
    else if (strstr(str, "ertificate")) g_sw_dtls_cp = 0x20005;
    else if (strstr(str, "cookie")) g_sw_dtls_cp = 0x20006;
    else if (strstr(str, "ragment")) g_sw_dtls_cp = 0x20007;
    else if (strstr(str, "alert")) g_sw_dtls_cp = 0x20008;
    else g_sw_dtls_cp = 0x2F000 | ((unsigned int)(str[0]) & 0xFF);  // unmatched: first char as a hint
  }
}
#endif

int dtls_srtp_init(DtlsSrtp* dtls_srtp, DtlsSrtpRole role, void* user_data) {
  static const mbedtls_ssl_srtp_profile default_profiles[] = {
      MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80,
      MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_32,
      MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_80,
      MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_32,
      MBEDTLS_TLS_SRTP_UNSET};

  dtls_srtp->role = role;
  dtls_srtp->state = DTLS_SRTP_STATE_INIT;
  dtls_srtp->user_data = user_data;
  dtls_srtp->udp_send = dtls_srtp_udp_send;
  dtls_srtp->udp_recv = dtls_srtp_udp_recv;

  mbedtls_ssl_config_init(&dtls_srtp->conf);
  mbedtls_ssl_init(&dtls_srtp->ssl);

  mbedtls_x509_crt_init(&dtls_srtp->cert);
  mbedtls_pk_init(&dtls_srtp->pkey);
  mbedtls_entropy_init(&dtls_srtp->entropy);
  mbedtls_ctr_drbg_init(&dtls_srtp->ctr_drbg);
#if CONFIG_MBEDTLS_DEBUG
  mbedtls_debug_set_threshold(3);
  mbedtls_ssl_conf_dbg(&dtls_srtp->conf, dtls_srtp_debug, NULL);
#endif
  dtls_srtp_selfsign_cert(dtls_srtp);

  mbedtls_ssl_conf_verify(&dtls_srtp->conf, dtls_srtp_cert_verify, NULL);

  mbedtls_ssl_conf_authmode(&dtls_srtp->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

  mbedtls_ssl_conf_ca_chain(&dtls_srtp->conf, &dtls_srtp->cert, NULL);

  mbedtls_ssl_conf_own_cert(&dtls_srtp->conf, &dtls_srtp->cert, &dtls_srtp->pkey);

  mbedtls_ssl_conf_rng(&dtls_srtp->conf, mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);

#if defined(MBEDTLS_CHACHAPOLY_C)
  // SpawnDev: ChaCha20-Poly1305 first, then mbedTLS's own order. On chips without GCM hardware (ESP32 classic) GCM's
  // GHASH runs from lookup tables, and with the cache shared and mbedTLS state in PSRAM a 1200-byte record took ~3 ms
  // to encrypt while video streamed (measured); ChaCha20-Poly1305 is plain register arithmetic. mbedTLS servers use
  // their own preference order, so this decides when we are the DTLS server; as a client it is our offer order.
  {
    static int suites[64];
    static int built = 0;
    if (!built) {
      int n = 0;
      suites[n++] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
      suites[n++] = MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
      for (const int* d = mbedtls_ssl_list_ciphersuites(); *d != 0 && n < 63; d++) {
        if (*d != suites[0] && *d != suites[1]) suites[n++] = *d;
      }
      suites[n] = 0;
      built = 1;
    }
    mbedtls_ssl_conf_ciphersuites(&dtls_srtp->conf, suites);
  }
#endif

  mbedtls_ssl_conf_read_timeout(&dtls_srtp->conf, 1000);

  if (dtls_srtp->role == DTLS_SRTP_ROLE_SERVER) {
    mbedtls_ssl_config_defaults(&dtls_srtp->conf,
                                MBEDTLS_SSL_IS_SERVER,
                                MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);

    mbedtls_ssl_cookie_init(&dtls_srtp->cookie_ctx);

    mbedtls_ssl_cookie_setup(&dtls_srtp->cookie_ctx, mbedtls_ctr_drbg_random, &dtls_srtp->ctr_drbg);

    // SpawnWear (Phase 7b): DISABLE DTLS cookies (HelloVerifyRequest). The peer is paired/known
    // (no DoS-amplification concern over the hub), and dropping the cookie removes the
    // session_reset retry loop, which is what makes the server handshake non-blockable.
    mbedtls_ssl_conf_dtls_cookies(&dtls_srtp->conf, NULL, NULL, NULL);

  } else {
    mbedtls_ssl_config_defaults(&dtls_srtp->conf,
                                MBEDTLS_SSL_IS_CLIENT,
                                MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
  }

  dtls_srtp_x509_digest(&dtls_srtp->cert, dtls_srtp->local_fingerprint);

  LOGD("local fingerprint: %s", dtls_srtp->local_fingerprint);

  mbedtls_ssl_conf_dtls_srtp_protection_profiles(&dtls_srtp->conf, default_profiles);

  mbedtls_ssl_conf_srtp_mki_value_supported(&dtls_srtp->conf, MBEDTLS_SSL_DTLS_SRTP_MKI_UNSUPPORTED);

  mbedtls_ssl_conf_cert_req_ca_list(&dtls_srtp->conf, MBEDTLS_SSL_CERT_REQ_CA_LIST_DISABLED);

  mbedtls_ssl_setup(&dtls_srtp->ssl, &dtls_srtp->conf);

  // SpawnWear (Phase 7c): as the DTLS CLIENT (verifying the peer's cert), mbedTLS 3.6+ refuses to
  // proceed unless mbedtls_ssl_set_hostname() was called explicitly, returning
  // MBEDTLS_ERR_SSL_CERTIFICATE_VERIFICATION_WITHOUT_HOSTNAME (-0x5D80) at SERVER_CERTIFICATE. WebRTC
  // has no hostname - identity is the cert FINGERPRINT (checked in dtls_srtp_handshake) - so opt out
  // explicitly with NULL. Harmless for the server role.
  mbedtls_ssl_set_hostname(&dtls_srtp->ssl, NULL);

  return 0;
}

void dtls_srtp_deinit(DtlsSrtp* dtls_srtp) {
  mbedtls_ssl_free(&dtls_srtp->ssl);
  mbedtls_ssl_config_free(&dtls_srtp->conf);

  mbedtls_x509_crt_free(&dtls_srtp->cert);
  mbedtls_pk_free(&dtls_srtp->pkey);
  mbedtls_entropy_free(&dtls_srtp->entropy);
  mbedtls_ctr_drbg_free(&dtls_srtp->ctr_drbg);

  if (dtls_srtp->role == DTLS_SRTP_ROLE_SERVER) {
    mbedtls_ssl_cookie_free(&dtls_srtp->cookie_ctx);
  }

  if (dtls_srtp->state == DTLS_SRTP_STATE_CONNECTED) {
    srtp_dealloc(dtls_srtp->srtp_in);
    srtp_dealloc(dtls_srtp->srtp_out);
  }
}

static int dtls_srtp_key_derivation(DtlsSrtp* dtls_srtp, const unsigned char* master_secret, size_t secret_len, const unsigned char* randbytes, size_t randbytes_len, mbedtls_tls_prf_types tls_prf_type) {
  int ret;
  const char* dtls_srtp_label = "EXTRACTOR-dtls_srtp";
  uint8_t key_material[DTLS_SRTP_KEY_MATERIAL_LENGTH];
  g_sw_dtls_cp = 2;  // SpawnWear: DTLS crypto done, deriving SRTP keys (srtp_create follows)
  // Export keying material
  if ((ret = mbedtls_ssl_tls_prf(tls_prf_type, master_secret, secret_len, dtls_srtp_label,
                                 randbytes, randbytes_len, key_material, sizeof(key_material))) != 0) {
    LOGE("mbedtls_ssl_tls_prf failed(%d)", ret);
    return ret;
  }

#if 0
  int i, j;
  printf("    DTLS-SRTP key material is:");
  for (j = 0; j < sizeof(key_material); j++) {
    if (j % 8 == 0) {
      printf("\n    ");
    }
    printf("%02x ", key_material[j]);
  }
  printf("\n");

  /* produce a less readable output used to perform automatic checks
   * - compare client and server output
   * - interop test with openssl which client produces this kind of output
   */
  printf("    Keying material: ");
  for (j = 0; j < sizeof(key_material); j++) {
    printf("%02X", key_material[j]);
  }
  printf("\n");
#endif

  const uint8_t* client_key = key_material;
  const uint8_t* server_key = client_key + SRTP_MASTER_KEY_LENGTH;
  const uint8_t* client_salt = server_key + SRTP_MASTER_KEY_LENGTH;
  const uint8_t* server_salt = client_salt + SRTP_MASTER_SALT_LENGTH;
  uint8_t *local_key, *remote_key, *local_salt, *remote_salt;
  if (dtls_srtp->role == DTLS_SRTP_ROLE_SERVER) {
    local_key = server_key;
    local_salt = server_salt;
    remote_key = client_key;
    remote_salt = client_salt;
  } else {
    local_key = client_key;
    local_salt = client_salt;
    remote_key = server_key;
    remote_salt = server_salt;
  }
  // derive inbounds keys

  memset(&dtls_srtp->remote_policy, 0, sizeof(dtls_srtp->remote_policy));

  srtp_crypto_policy_set_rtp_default(&dtls_srtp->remote_policy.rtp);
  srtp_crypto_policy_set_rtcp_default(&dtls_srtp->remote_policy.rtcp);

  memcpy(dtls_srtp->remote_policy_key, remote_key, SRTP_MASTER_KEY_LENGTH);
  memcpy(dtls_srtp->remote_policy_key + SRTP_MASTER_KEY_LENGTH, remote_salt, SRTP_MASTER_SALT_LENGTH);

  dtls_srtp->remote_policy.ssrc.type = ssrc_any_inbound;
  dtls_srtp->remote_policy.key = dtls_srtp->remote_policy_key;
  dtls_srtp->remote_policy.next = NULL;

  if (srtp_create(&dtls_srtp->srtp_in, &dtls_srtp->remote_policy) != srtp_err_status_ok) {
    LOGD("Error creating inbound SRTP session for component");
    return -1;
  }

  LOGI("Created inbound SRTP session");

  // derive outbounds keys
  memset(&dtls_srtp->local_policy, 0, sizeof(dtls_srtp->local_policy));

  srtp_crypto_policy_set_rtp_default(&dtls_srtp->local_policy.rtp);
  srtp_crypto_policy_set_rtcp_default(&dtls_srtp->local_policy.rtcp);

  memcpy(dtls_srtp->local_policy_key, local_key, SRTP_MASTER_KEY_LENGTH);
  memcpy(dtls_srtp->local_policy_key + SRTP_MASTER_KEY_LENGTH, local_salt, SRTP_MASTER_SALT_LENGTH);

  dtls_srtp->local_policy.ssrc.type = ssrc_any_outbound;
  dtls_srtp->local_policy.key = dtls_srtp->local_policy_key;
  dtls_srtp->local_policy.next = NULL;

  if (srtp_create(&dtls_srtp->srtp_out, &dtls_srtp->local_policy) != srtp_err_status_ok) {
    LOGE("Error creating outbound SRTP session");
    return -1;
  }

  LOGI("Created outbound SRTP session");
  dtls_srtp->state = DTLS_SRTP_STATE_CONNECTED;
  return 0;
}

#if CONFIG_MBEDTLS_2_X
static int dtls_srtp_key_derivation_cb(void* context,
                                       const unsigned char* ms,
                                       const unsigned char* kb,
                                       size_t maclen,
                                       size_t keylen,
                                       size_t ivlen,
                                       const unsigned char client_random[32],
                                       const unsigned char server_random[32],
                                       mbedtls_tls_prf_types tls_prf_type) {
#else
static void dtls_srtp_key_derivation_cb(void* context,
                                        mbedtls_ssl_key_export_type secret_type,
                                        const unsigned char* secret,
                                        size_t secret_len,
                                        const unsigned char client_random[32],
                                        const unsigned char server_random[32],
                                        mbedtls_tls_prf_types tls_prf_type) {
#endif
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)context;

  unsigned char master_secret[48];
  unsigned char randbytes[64];

  memcpy(randbytes, client_random, 32);
  memcpy(randbytes + 32, server_random, 32);

#if CONFIG_MBEDTLS_2_X
  memcpy(master_secret, ms, sizeof(master_secret));
  return dtls_srtp_key_derivation(dtls_srtp, master_secret, sizeof(master_secret), randbytes, sizeof(randbytes), tls_prf_type);
#else
  memcpy(master_secret, secret, sizeof(master_secret));
  dtls_srtp_key_derivation(dtls_srtp, master_secret, sizeof(master_secret), randbytes, sizeof(randbytes), tls_prf_type);
#endif
}

static int dtls_srtp_do_handshake(DtlsSrtp* dtls_srtp) {
  int ret;

  static mbedtls_timing_delay_context timer;

  // SpawnDev: install the timer ONCE per handshake. mbedtls_ssl_set_timer_cb ends with mbedtls_ssl_set_timer(ssl, 0),
  // i.e. it CANCELS the running timer, and this function runs on every pump pass of the non-blocking handshake, so
  // the retransmission timer was reset every ~10 ms and never fired: a lost first flight was never resent (measured:
  // ClientHello sent once, nothing received, mbedTLS state 2 for 30 s; the "no working non-blocking retransmission"
  // that the answerer's start delay below works around). A fresh ssl context has p_timer NULL.
  if (dtls_srtp->ssl.MBEDTLS_PRIVATE(p_timer) != &timer) {
    mbedtls_ssl_set_timer_cb(&dtls_srtp->ssl, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
  }

#if CONFIG_MBEDTLS_2_X
  mbedtls_ssl_conf_export_keys_ext_cb(&dtls_srtp->conf, dtls_srtp_key_derivation_cb, dtls_srtp);
#else
  mbedtls_ssl_set_export_keys_cb(&dtls_srtp->ssl, dtls_srtp_key_derivation_cb, dtls_srtp);
#endif

  // SpawnWear (watch-answers-offers): f_recv_timeout stays NULL. Wiring a non-blocking f_recv_timeout that
  // returns MBEDTLS_ERR_SSL_TIMEOUT made mbedtls BUSY-WAIT (re-call it for the full ~1s retransmission
  // timeout) holding the pump mutex -> ~2s cooperative-CLR FREEZE that regressed even the offer path. The
  // non-blocking pump can't satisfy a blocking f_recv_timeout. Instead the ANSWERER's dropped-ClientHello
  // timing is handled by DELAYING its DTLS start (peer_connection_loop CONNECTED) until the peer's DTLS is
  // up - no retransmission needed. (udp_recv_timeout left wired in state_new but unused = harmless.)
  mbedtls_ssl_set_bio(&dtls_srtp->ssl, dtls_srtp, dtls_srtp->udp_send, dtls_srtp->udp_recv, NULL);

  // SpawnWear (Phase 7b): NON-BLOCKING - call once and return WANT_READ/WANT_WRITE up to
  // peer_connection_loop (the original do-while spun here, holding the pump mutex => froze the
  // watch). mbedtls keeps the handshake state in ssl across calls; the timer above is static.
  ret = mbedtls_ssl_handshake(&dtls_srtp->ssl);

  return ret;
}

static int dtls_srtp_handshake_server(DtlsSrtp* dtls_srtp) {
  // SpawnWear (Phase 7b): NON-BLOCKING + DTLS cookies disabled (see dtls_srtp_init), so there is
  // no HelloVerifyRequest and no session_reset retry loop - just drive one handshake step. The
  // original while(1) + mbedtls_ssl_session_reset() assumed a blocking recv and RESET the
  // handshake on every peer_connection_loop iteration, so a non-blocking handshake could never
  // make progress. WANT_READ/WANT_WRITE propagate up; mbedtls keeps its own handshake state.
  return dtls_srtp_do_handshake(dtls_srtp);
}

static int dtls_srtp_handshake_client(DtlsSrtp* dtls_srtp) {
  int ret;

  ret = dtls_srtp_do_handshake(dtls_srtp);
  // SpawnWear (Phase 7c): the handshake is non-blocking, so WANT_READ/WANT_WRITE are NORMAL
  // (the client steps the handshake across many peer_connection_loop calls). Only log a real error.
  if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
    LOGE("failed! mbedtls_ssl_handshake returned -0x%.4x\n\n", (unsigned int)-ret);
  }

  return ret;
}

int dtls_srtp_handshake(DtlsSrtp* dtls_srtp, Address* addr) {
  int ret;
  dtls_srtp->remote_addr = addr;
  g_sw_dtls_cp = 1;  // SpawnWear: DTLS handshake entered

  if (dtls_srtp->role == DTLS_SRTP_ROLE_SERVER) {
    ret = dtls_srtp_handshake_server(dtls_srtp);
  } else {
    ret = dtls_srtp_handshake_client(dtls_srtp);
  }

  // SpawnWear (Phase 7b): NON-BLOCKING - if the handshake isn't complete yet (WANT_READ /
  // WANT_WRITE) or it errored, return now. The fingerprint check below dereferences the peer
  // cert, which only exists once the handshake is DONE (ret == 0); running it mid-handshake
  // returned -1 ("no remote fingerprint"). peer_connection_loop re-enters next iteration.
  if (ret != 0) {
    // not complete yet (WANT_READ) or a fatal error; peer_connection_loop re-enters. Record the
    // mbedtls error magnitude (read via GetState(-1) as 0x10000|err) UNLESS an in-mbedtls
    // instrumentation point already set a 0x3xxxx reason code.
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && g_sw_dtls_cp < 0x30000u) {
      // SpawnWear 7b: pack the mbedtls handshake state alongside the error magnitude so we can name
      // WHICH step failed. Value = 0x40_SS_EEEE (top byte 0x40 = marker, SS = ssl.state, EEEE = -ret).
      // state enum: 2=ServerHello 3=ServerCert 4=ServerKeyExchange 7=ClientCert 8=ClientKeyExchange
      // 9=CertVerify 13=ServerFinished. (e.g. 0x40086E00 = ClientKeyExchange + HANDSHAKE_FAILURE)
      unsigned int st = (unsigned int)dtls_srtp->ssl.MBEDTLS_PRIVATE(state) & 0xFFu;
      g_sw_dtls_cp = (0x40u << 24) | (st << 16) | ((unsigned int)(-ret) & 0xFFFFu);
    }
    return ret;
  }

  const mbedtls_x509_crt* remote_crt;
  if ((remote_crt = mbedtls_ssl_get_peer_cert(&dtls_srtp->ssl)) != NULL) {
    dtls_srtp_x509_digest(remote_crt, dtls_srtp->actual_remote_fingerprint);

    if (strncmp(dtls_srtp->remote_fingerprint, dtls_srtp->actual_remote_fingerprint, DTLS_SRTP_FINGERPRINT_LENGTH) != 0) {
      LOGE("Actual and Expected Fingerprint mismatch: %s %s",
           dtls_srtp->remote_fingerprint,
           dtls_srtp->actual_remote_fingerprint);
      return -1;
    }

  } else {
    LOGE("no remote fingerprint");
    return -1;
  }

  mbedtls_dtls_srtp_info dtls_srtp_negotiation_result;
  mbedtls_ssl_get_dtls_srtp_negotiation_result(&dtls_srtp->ssl, &dtls_srtp_negotiation_result);

  g_sw_dtls_cp = 4;  // SpawnWear: DTLS handshake fully returned (crypto + SRTP + fingerprint ok)
  return ret;
}

void dtls_srtp_reset_session(DtlsSrtp* dtls_srtp) {
  if (dtls_srtp->state == DTLS_SRTP_STATE_CONNECTED) {
    srtp_dealloc(dtls_srtp->srtp_in);
    srtp_dealloc(dtls_srtp->srtp_out);
    mbedtls_ssl_session_reset(&dtls_srtp->ssl);
  }

  dtls_srtp->state = DTLS_SRTP_STATE_INIT;
}

int dtls_srtp_write(DtlsSrtp* dtls_srtp, const unsigned char* buf, size_t len) {
  int ret;
  int64_t t0 = SD_NOW_US();

  do {
    ret = mbedtls_ssl_write(&dtls_srtp->ssl, buf, len);

  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
  g_dtls_write_us += (uint32_t)(SD_NOW_US() - t0);
  g_dtls_writes++;
  return ret;
}

int dtls_srtp_read(DtlsSrtp* dtls_srtp, unsigned char* buf, size_t len) {
  int ret;

  memset(buf, 0, len);

  do {
    ret = mbedtls_ssl_read(&dtls_srtp->ssl, buf, len);

  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  return ret;
}

int dtls_srtp_probe(uint8_t* buf) {
  if (buf == NULL)
    return 0;

  LOGD("DTLS content type: %d", buf[0]);
  // only handle application data
  return (buf[0] == 0x17);
}

void dtls_srtp_decrypt_rtp_packet(DtlsSrtp* dtls_srtp, uint8_t* packet, int* bytes) {
  srtp_unprotect(dtls_srtp->srtp_in, packet, bytes);
}

void dtls_srtp_decrypt_rtcp_packet(DtlsSrtp* dtls_srtp, uint8_t* packet, int* bytes) {
  srtp_unprotect_rtcp(dtls_srtp->srtp_in, packet, bytes);
}

void dtls_srtp_encrypt_rtp_packet(DtlsSrtp* dtls_srtp, uint8_t* packet, int* bytes) {
  srtp_protect(dtls_srtp->srtp_out, packet, bytes);
}

void dtls_srtp_encrypt_rctp_packet(DtlsSrtp* dtls_srtp, uint8_t* packet, int* bytes) {
  srtp_protect_rtcp(dtls_srtp->srtp_out, packet, bytes);
}
