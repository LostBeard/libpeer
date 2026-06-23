#ifndef CONFIG_H_
#define CONFIG_H_

// uncomment this if you want to handshake with a aiortc
// SpawnWear (Phase 7b 2026-06-23): ENABLED. The watch is the DTLS SERVER answering SipSorcery
// (ECDSA P-256 cert), which offers ONLY ECDHE-ECDSA ciphersuites. With this 0 (RSA cert), the
// watch found the common suite but mbedtls_pk_can_do(RSA_key, ECDSA) failed in ssl_pick_cert
// -> 0x30041 -> "no usable ciphersuite" -> handshake_failure(40)/-0x6E00 at CLIENT_HELLO (state=1).
// ECDSA P-256 is the WebRTC standard (Chrome/Firefox/aiortc/SipSorcery) and cheap on ESP32.
#define CONFIG_DTLS_USE_ECDSA 1

#define SCTP_MTU (1200)
#define CONFIG_MTU (1300)

#ifndef CONFIG_USE_LWIP
#define CONFIG_USE_LWIP 0
#endif

#ifndef CONFIG_MBEDTLS_DEBUG
#define CONFIG_MBEDTLS_DEBUG 0
#endif

#ifndef CONFIG_MBEDTLS_2_X
#define CONFIG_MBEDTLS_2_X 0
#endif

#if CONFIG_MBEDTLS_2_X
#define RSA_KEY_LENGTH 512
#else
#define RSA_KEY_LENGTH 1024
#endif

#ifndef CONFIG_DTLS_USE_ECDSA
#define CONFIG_DTLS_USE_ECDSA 0
#endif

#ifndef CONFIG_USE_USRSCTP
#define CONFIG_USE_USRSCTP 1
#endif

#ifndef CONFIG_VIDEO_BUFFER_SIZE
#define CONFIG_VIDEO_BUFFER_SIZE (CONFIG_MTU * 256)
#endif

#ifndef CONFIG_AUDIO_BUFFER_SIZE
#define CONFIG_AUDIO_BUFFER_SIZE (CONFIG_MTU * 256)
#endif

#ifndef CONFIG_DATA_BUFFER_SIZE
#define CONFIG_DATA_BUFFER_SIZE (SCTP_MTU * 128)
#endif

#ifndef CONFIG_SDP_BUFFER_SIZE
#define CONFIG_SDP_BUFFER_SIZE 8096
#endif

#ifndef CONFIG_MQTT_BUFFER_SIZE
#define CONFIG_MQTT_BUFFER_SIZE 4096
#endif

#ifndef CONFIG_HTTP_BUFFER_SIZE
#define CONFIG_HTTP_BUFFER_SIZE 4096
#endif

#ifndef CONFIG_TLS_READ_TIMEOUT
#define CONFIG_TLS_READ_TIMEOUT 3000
#endif

#ifndef CONFIG_KEEPALIVE_TIMEOUT
#define CONFIG_KEEPALIVE_TIMEOUT 10000
#endif

#ifndef CONFIG_AUDIO_DURATION
#define CONFIG_AUDIO_DURATION 20
#endif

#define CONFIG_IPV6 0
// empty will use first active interface
#define CONFIG_IFACE_PREFIX ""

// #define LOG_LEVEL LEVEL_DEBUG
#define LOG_REDIRECT 0

// Disable MQTT and HTTP signaling
// #define DISABLE_PEER_SIGNALING 1

#endif  // CONFIG_H_
