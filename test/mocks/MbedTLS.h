#ifndef MBEDTLS_MOCK_H
#define MBEDTLS_MOCK_H

#include <Arduino.h>

// #define MBEDTLS_ERROR_C
#define MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED
#define MBEDTLS_ERR_SSL_WANT_READ               -0x6900
#define MBEDTLS_ERR_NET_SEND_FAILED             -0x004E
#define MBEDTLS_SSL_IS_CLIENT                   0
#define MBEDTLS_SSL_TRANSPORT_STREAM            0
#define MBEDTLS_SSL_PRESET_DEFAULT              0
#define MBEDTLS_SSL_VERIFY_REQUIRED             2
#define MBEDTLS_PSK_MAX_LEN                     32
#define MBEDTLS_SSL_VERIFY_NONE                 0
#define MBEDTLS_ERR_SSL_WANT_WRITE              -0x6880
#define MBEDTLS_OID_ISO_CCITT_DS                "\x55"
#define MBEDTLS_OID_AT                          MBEDTLS_OID_ISO_CCITT_DS "\x04"
#define MBEDTLS_OID_AT_CN                       MBEDTLS_OID_AT "\x03"
#define MBEDTLS_OID_CMP(oid_str, oid_buf)       (strncmp((oid_str), (char*)(oid_buf)->p, (oid_buf)->len) == 0)

typedef struct mbedtls_asn1_buf {
  int tag;
  size_t len;
  unsigned char *p;
} mbedtls_asn1_buf;

typedef struct mbedtls_asn1_named_data {
  mbedtls_asn1_buf oid;
  mbedtls_asn1_buf val;
  struct mbedtls_asn1_named_data *next;
  unsigned char next_merged;
} mbedtls_asn1_named_data;

typedef struct mbedtls_asn1_sequence {
  mbedtls_asn1_buf buf;
  struct mbedtls_asn1_sequence *next;
} mbedtls_asn1_sequence;

typedef mbedtls_asn1_sequence mbedtls_x509_sequence;

typedef int mbedtls_ssl_send_t(void *ctx, const unsigned char *buf, size_t len);
typedef int mbedtls_ssl_recv_t(void *ctx, unsigned char *buf, size_t len);
typedef int mbedtls_ssl_recv_timeout_t(void *ctx, unsigned char *buf, size_t len, uint32_t timeout);

struct mbedtls_ssl_context {};
struct mbedtls_ctr_drbg_context {};
struct mbedtls_entropy_context {};
struct mbedtls_ssl_config {
  void* ca_chain;
  void* key_cert;
};
struct rawStruct {
  const unsigned char *p;
  size_t len;
};
struct mbedtls_x509_crt {
  rawStruct raw;
  mbedtls_x509_sequence subject_alt_names;
  mbedtls_asn1_named_data subject;
};
struct mbedtls_x509_crl {};
struct mbedtls_pk_context {};
struct mbedtls_sha256_context {
  uint32_t total[2];
  uint32_t state[8];
  unsigned char buffer[64];
  int is224;
};

const mbedtls_x509_crt dummy_cert = {
    {NULL, 0},  // raw (rawStruct)

    // subject_alt_names (mbedtls_x509_sequence)
    {
      {0, 0, NULL}, // buf (mbedtls_asn1_buf)
      NULL         // next
    },

    // subject (mbedtls_asn1_named_data)
    {
      {0, 0, NULL}, // oid (mbedtls_asn1_buf)
      {0, 0, NULL}, // val (mbedtls_asn1_buf)
      NULL,         // next
      0             // next_merged (unsigned char)
    }
};

const mbedtls_x509_crt *mbedtls_ssl_get_peer_cert(const mbedtls_ssl_context *ssl) { return &dummy_cert; }

void mbedtls_ssl_init(mbedtls_ssl_context *ssl) {}
void mbedtls_ssl_config_init(mbedtls_ssl_config *conf) {}
void mbedtls_entropy_init(mbedtls_entropy_context *ctx) {}
void mbedtls_ctr_drbg_init(mbedtls_ctr_drbg_context *ctx) {}
void mbedtls_x509_crt_init(mbedtls_x509_crt *crt) {}
void mbedtls_ssl_conf_authmode(mbedtls_ssl_config *conf, int authmode) {}
void mbedtls_ssl_conf_ca_chain(mbedtls_ssl_config *conf, mbedtls_x509_crt *ca_chain, mbedtls_x509_crl *ca_crl) {}
void mbedtls_pk_init(mbedtls_pk_context *ctx) {}
void mbedtls_x509_crt_free(mbedtls_x509_crt *crt) {}
void mbedtls_ssl_conf_rng(mbedtls_ssl_config *conf, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng) {}
void mbedtls_ssl_set_bio( mbedtls_ssl_context *ssl, void *p_bio, mbedtls_ssl_send_t *f_send, mbedtls_ssl_recv_t *f_recv, mbedtls_ssl_recv_timeout_t *f_recv_timeout) {}
void mbedtls_pk_free(mbedtls_pk_context *ctx) {}
void mbedtls_ssl_free(mbedtls_ssl_context *ssl) {}
void mbedtls_ssl_config_free(mbedtls_ssl_config *conf) {}
void mbedtls_ctr_drbg_free(mbedtls_ctr_drbg_context *ctx) {}
void mbedtls_entropy_free(mbedtls_entropy_context *ctx) {}
void mbedtls_sha256_init(mbedtls_sha256_context *ctx) {}
void mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224) {}
void mbedtls_sha256_update(mbedtls_sha256_context *ctx, const unsigned char *input, size_t ilen) {}
void mbedtls_sha256_finish(mbedtls_sha256_context *ctx, unsigned char output[32]) {}

uint32_t mbedtls_ssl_get_verify_result(const mbedtls_ssl_context *ssl) { return (uint32_t)0; }
size_t mbedtls_ssl_get_bytes_avail(const mbedtls_ssl_context *ssl) { return (size_t)0; }

int mbedtls_ctr_drbg_seed_returns = 0;
int mbedtls_entropy_func_returns = 0;
int mbedtls_ssl_config_defaults_returns = 0;
int mbedtls_x509_crt_parse_returns = 0;
int mbedtls_ssl_conf_psk_returns = 0;
int mbedtls_pk_parse_key_returns = 0;
int mbedtls_ssl_conf_own_cert_returns = 0;
int mbedtls_ssl_set_hostname_returns = 0;
int mbedtls_ctr_drbg_random_returns = 0;
int mbedtls_ssl_setup_returns = 0;
int mbedtls_ssl_handshake_returns = 0;
int mbedtls_ssl_get_record_expansion_returns = 0;
int mbedtls_x509_crt_verify_info_returns = 0;
int mbedtls_ssl_read_returns = 0;
int mbedtls_ssl_write_returns = 0;

void mbedtls_mock_reset_return_values() {
  mbedtls_ctr_drbg_seed_returns = 0;
  mbedtls_entropy_func_returns = 0;
  mbedtls_ssl_config_defaults_returns = 0;
  mbedtls_x509_crt_parse_returns = 0;
  mbedtls_ssl_conf_psk_returns = 0;
  mbedtls_pk_parse_key_returns = 0;
  mbedtls_ssl_conf_own_cert_returns = 0;
  mbedtls_ssl_set_hostname_returns = 0;
  mbedtls_ctr_drbg_random_returns = 0;
  mbedtls_ssl_setup_returns = 0;
  mbedtls_ssl_handshake_returns = 0;
  mbedtls_ssl_get_record_expansion_returns = 0;
  mbedtls_x509_crt_verify_info_returns = 0;
  mbedtls_ssl_read_returns = 0;
  mbedtls_ssl_write_returns = 0;
}

int mbedtls_ctr_drbg_seed(mbedtls_ctr_drbg_context *ctx, int (*f_entropy)(void *, unsigned char *, size_t), void *p_entropy, const unsigned char *custom, size_t len) { return mbedtls_ctr_drbg_seed_returns; }
int mbedtls_entropy_func(void *data, unsigned char *output, size_t len) { return mbedtls_entropy_func_returns; }
int mbedtls_ssl_config_defaults(mbedtls_ssl_config *conf, int endpoint, int transport, int preset) { return mbedtls_ssl_config_defaults_returns; }
int mbedtls_x509_crt_parse(mbedtls_x509_crt *chain, const unsigned char *buf, size_t buflen) { return mbedtls_x509_crt_parse_returns; }
int mbedtls_ssl_conf_psk(mbedtls_ssl_config *conf, const unsigned char *psk, size_t psk_len, const unsigned char *psk_identity, size_t psk_identity_len) { return mbedtls_ssl_conf_psk_returns; }
int mbedtls_pk_parse_key(mbedtls_pk_context *pk, const unsigned char *key, size_t keylen, const unsigned char *pwd, size_t pwdlen) { return mbedtls_pk_parse_key_returns; }
int mbedtls_ssl_conf_own_cert(mbedtls_ssl_config *conf, mbedtls_x509_crt *own_cert, mbedtls_pk_context *pk_key) { return mbedtls_ssl_conf_own_cert_returns; }
int mbedtls_ssl_set_hostname(mbedtls_ssl_context *ssl, const char *hostname) { return mbedtls_ssl_set_hostname_returns; }
int mbedtls_ctr_drbg_random(void *p_rng, unsigned char *output, size_t output_len) { return mbedtls_ctr_drbg_random_returns; }
int mbedtls_ssl_setup(mbedtls_ssl_context *ssl, const mbedtls_ssl_config *conf) { return mbedtls_ssl_setup_returns; }
int mbedtls_ssl_handshake(mbedtls_ssl_context *ssl) { return mbedtls_ssl_handshake_returns; }
int mbedtls_ssl_get_record_expansion(const mbedtls_ssl_context *ssl) { return mbedtls_ssl_get_record_expansion_returns; }
int mbedtls_x509_crt_verify_info(char *buf, size_t size, const char *prefix, uint32_t flags) { return mbedtls_x509_crt_verify_info_returns; }
int mbedtls_ssl_read(mbedtls_ssl_context *ssl, unsigned char *buf, size_t len) { return mbedtls_ssl_read_returns; }
int mbedtls_ssl_write(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len) { return mbedtls_ssl_write_returns; }

const char *mbedtls_ssl_get_version(const mbedtls_ssl_context *ssl) { return (const char*)""; }
const char *mbedtls_ssl_get_ciphersuite(const mbedtls_ssl_context *ssl) { return (const char*)""; }

#endif // MBEDTLS_MOCK_H