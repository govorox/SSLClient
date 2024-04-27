#ifndef MBEDTLS_MOCK_H
#define MBEDTLS_MOCK_H

#include <FunctionEmulator.h>

// #define MBEDTLS_ERROR_C
#define MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED
#define MBEDTLS_X509_BADCERT_EXPIRED                -0x01
#define MBEDTLS_X509_BADCERT_NOT_TRUSTED            -0x08
#define MBEDTLS_X509_BADCERT_BAD_MD                 -0x4000
#define MBEDTLS_ERR_X509_CERT_VERIFY_FAILED         -0x2700
#define MBEDTLS_X509_BADCERT_OTHER                  -0x0100
#define MBEDTLS_ERR_SSL_WANT_READ                   -0x6900
#define MBEDTLS_ERR_NET_SEND_FAILED                 -0x004E
#define MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED  -0x0034
#define MBEDTLS_ERR_SSL_ALLOC_FAILED                -0x7F00
#define MBEDTLS_ERR_SSL_BAD_INPUT_DATA              -0x7100
#define MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE         -0x7080
#define MBEDTLS_ERR_SSL_WANT_WRITE                  -0x6880
#define MBEDTLS_ERR_NET_CONN_RESET                  -0x004C
#define MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE         -0x7780
#define MBEDTLS_ERR_X509_FATAL_ERROR                -0x3000
#define MBEDTLS_SSL_IS_CLIENT                       0
#define MBEDTLS_SSL_TRANSPORT_STREAM                0
#define MBEDTLS_SSL_PRESET_DEFAULT                  0
#define MBEDTLS_SSL_VERIFY_REQUIRED                 2
#define MBEDTLS_PSK_MAX_LEN                         32
#define MBEDTLS_SSL_VERIFY_NONE                     0
#define MBEDTLS_OID_ISO_CCITT_DS                    "\x55"
#define MBEDTLS_OID_AT                              "\x55\x04"
#define MBEDTLS_OID_AT_CN                           "\x55\x04\x03"
#define MBEDTLS_OID_CMP(oid_str, oid_buf)           (false)
#define MBEDTLS_ASN1_IA5_STRING                     0x16
#define MBEDTLS_ASN1_OID                            0x06
#define MBEDTLS_MD_MAX_SIZE                         32
#define ESP_ERR_NO_MEM                              0x101

struct mbedtls_pk_context {};

typedef enum {
  MBEDTLS_MD_NONE=0,
  MBEDTLS_MD_MD2,
  MBEDTLS_MD_MD4,
  MBEDTLS_MD_MD5,
  MBEDTLS_MD_SHA1,
  MBEDTLS_MD_SHA224,
  MBEDTLS_MD_SHA256,
  MBEDTLS_MD_SHA384,
  MBEDTLS_MD_SHA512,
  MBEDTLS_MD_RIPEMD160,
} mbedtls_md_type_t;

typedef enum {
  MBEDTLS_PK_NONE=0,
  MBEDTLS_PK_RSA,
  MBEDTLS_PK_ECKEY,
  MBEDTLS_PK_ECKEY_DH,
  MBEDTLS_PK_ECDSA,
  MBEDTLS_PK_RSA_ALT,
  MBEDTLS_PK_RSASSA_PSS
} mbedtls_pk_type_t;

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
typedef mbedtls_asn1_buf mbedtls_x509_buf;

typedef int mbedtls_ssl_send_t(void *ctx, const unsigned char *buf, size_t len);
typedef int mbedtls_ssl_recv_t(void *ctx, unsigned char *buf, size_t len);
typedef int mbedtls_ssl_recv_timeout_t(void *ctx, unsigned char *buf, size_t len, uint32_t timeout);

struct mbedtls_ssl_context {};
struct mbedtls_ctr_drbg_context {};
struct mbedtls_entropy_context {};
struct rawStruct {
  const unsigned char *p;
  size_t len;
};
struct mbedtls_x509_crt {
  rawStruct raw;
  mbedtls_x509_sequence subject_alt_names;
  mbedtls_asn1_named_data subject;
  mbedtls_pk_context pk;
  mbedtls_x509_buf sig;
  mbedtls_pk_type_t sig_pk;
  mbedtls_md_type_t sig_md;
  void *sig_opts;
  mbedtls_x509_buf issuer_raw;
  mbedtls_x509_buf tbs; 
};
struct mbedtls_ssl_config {
  void* ca_chain;
  void* key_cert;
  mbedtls_x509_crt* actual_ca_chain;
  mbedtls_x509_crt* actual_key_cert;
};
struct mbedtls_x509_crl {};
struct mbedtls_sha256_context {
  uint32_t total[2];
  uint32_t state[8];
  unsigned char buffer[64];
  int is224;
};

struct mbedtls_md_info_t {
  mbedtls_md_type_t type;
  const char * name;
  int size;
  int block_size;
  void (*starts_func)( void *ctx );
  void (*update_func)( void *ctx, const unsigned char *input, size_t ilen );
  void (*finish_func)( void *ctx, unsigned char *output );
  void (*digest_func)( const unsigned char *input, size_t ilen, unsigned char *output );
  void * (*ctx_alloc_func)( void );
  void (*ctx_free_func)( void *ctx );
  void (*clone_func)( void *dst, const void *src );
  void (*process_func)( void *ctx, const unsigned char *input );
};

const char* mock_cert_data = "MockCertificateData";

mbedtls_x509_crt dummy_cert = {
  {reinterpret_cast<const unsigned char*>(mock_cert_data), strlen(mock_cert_data)},

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

std::string dName = "example.com";
size_t len = dName.length();
unsigned char* uchar_ptr = reinterpret_cast<unsigned char*>(&dName[0]);

mbedtls_asn1_buf example_com_buffer = {
  MBEDTLS_ASN1_IA5_STRING,
  len,
  uchar_ptr
};

mbedtls_x509_sequence example_com_sequence = {
  example_com_buffer,
  NULL
};

mbedtls_x509_crt dummy_cert_with_san = {
  {reinterpret_cast<const unsigned char*>(mock_cert_data), strlen(mock_cert_data)},
  example_com_sequence,
  {
    {0, 0, NULL},
    {0, 0, NULL},
    NULL,
    0
  }
};

mbedtls_x509_crt dummy_cert_with_cn = {
  {reinterpret_cast<const unsigned char*>(mock_cert_data), strlen(mock_cert_data)},
  {
    {0, 0, NULL},
    NULL
  },
  {
    {MBEDTLS_ASN1_OID, sizeof(MBEDTLS_OID_AT_CN) - 1, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(MBEDTLS_OID_AT_CN))},
    {MBEDTLS_ASN1_IA5_STRING, strlen("example.com"), const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>("example.com"))},
    NULL,
    0
  }
};

mbedtls_x509_crt dummy_cert_without_match = {
  {reinterpret_cast<const unsigned char*>(mock_cert_data), strlen(mock_cert_data)},
  {
    {strlen("notexample.com"), MBEDTLS_ASN1_IA5_STRING, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>("notexample.com"))},
    NULL
  },
  {
    {sizeof(MBEDTLS_OID_AT_CN) - 1, MBEDTLS_ASN1_OID, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(MBEDTLS_OID_AT_CN))},
    {strlen("notexample.com"), MBEDTLS_ASN1_IA5_STRING, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>("notexample.com"))},
    NULL,
    0
  }
};

// Const removed from mbedtls_ssl_get_peer_cert for mocking - const mbedtls_x509_crt *
FunctionEmulator mbedtls_ssl_get_peer_cert_stub("mbedtls_ssl_get_peer_cert");
mbedtls_x509_crt *mbedtls_ssl_get_peer_cert(const mbedtls_ssl_context *ssl) {
  mbedtls_ssl_get_peer_cert_stub.recordFunctionCall();
  return mbedtls_ssl_get_peer_cert_stub.mock<mbedtls_x509_crt*>("mbedtls_ssl_get_peer_cert");
}

FunctionEmulator mbedtls_ssl_init_stub("mbedtls_ssl_init");
void mbedtls_ssl_init(mbedtls_ssl_context *ssl) {
  mbedtls_ssl_init_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_ssl_config_init_stub("mbedtls_ssl_config_init");
void mbedtls_ssl_config_init(mbedtls_ssl_config *conf) {
  mbedtls_ssl_config_init_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_entropy_init_stub("mbedtls_entropy_init");
void mbedtls_entropy_init(mbedtls_entropy_context *ctx) {
  mbedtls_entropy_init_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_ctr_drbg_init_stub("mbedtls_ctr_drbg_init");
void mbedtls_ctr_drbg_init(mbedtls_ctr_drbg_context *ctx) {
  mbedtls_ctr_drbg_init_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_x509_crt_init_stub("mbedtls_x509_crt_init");
void mbedtls_x509_crt_init(mbedtls_x509_crt *crt) {
  mbedtls_x509_crt_init_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_ssl_conf_authmode_stub("mbedtls_ssl_conf_authmode");
void mbedtls_ssl_conf_authmode(mbedtls_ssl_config *conf, int authmode) {
  mbedtls_ssl_conf_authmode_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_ssl_conf_ca_chain_stub("mbedtls_ssl_conf_ca_chain");
void mbedtls_ssl_conf_ca_chain(mbedtls_ssl_config *conf, mbedtls_x509_crt *ca_chain, mbedtls_x509_crl *ca_crl) {
  mbedtls_ssl_conf_ca_chain_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_pk_init_stub("mbedtls_pk_init");
void mbedtls_pk_init(mbedtls_pk_context *ctx) {
  mbedtls_pk_init_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_x509_crt_free_stub("mbedtls_x509_crt_free");
void   mbedtls_x509_crt_free(mbedtls_x509_crt *crt) {
  mbedtls_x509_crt_free_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_ssl_conf_rng_stub("mbedtls_ssl_conf_rng");
void mbedtls_ssl_conf_rng(mbedtls_ssl_config *conf, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng) {
  mbedtls_ssl_conf_rng_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_ssl_set_bio_stub("mbedtls_ssl_set_bio");
void mbedtls_ssl_set_bio( mbedtls_ssl_context *ssl, void *p_bio, mbedtls_ssl_send_t *f_send, mbedtls_ssl_recv_t *f_recv, mbedtls_ssl_recv_timeout_t *f_recv_timeout) {
  mbedtls_ssl_set_bio_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_ssl_conf_read_timeout_stub("mbedtls_ssl_conf_read_timeout");
void mbedtls_ssl_conf_read_timeout(mbedtls_ssl_config *conf, uint32_t timeout) {
  mbedtls_ssl_conf_read_timeout_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_pk_free_stub("mbedtls_pk_free");
void mbedtls_pk_free(mbedtls_pk_context *ctx) {
  mbedtls_pk_free_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_ssl_free_stub("mbedtls_ssl_free");
void mbedtls_ssl_free(mbedtls_ssl_context *ssl) {
  mbedtls_ssl_free_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_ssl_config_free_stub("mbedtls_ssl_config_free");
void mbedtls_ssl_config_free(mbedtls_ssl_config *conf) {
  mbedtls_ssl_config_free_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_ctr_drbg_free_stub("mbedtls_ctr_drbg_free");
void mbedtls_ctr_drbg_free(mbedtls_ctr_drbg_context *ctx) {
  mbedtls_ctr_drbg_free_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_entropy_free_stub("mbedtls_entropy_free");
void mbedtls_entropy_free(mbedtls_entropy_context *ctx) {
  mbedtls_entropy_free_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_sha256_init_stub("mbedtls_sha256_init");
void mbedtls_sha256_init(mbedtls_sha256_context *ctx) {
  mbedtls_sha256_init_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_sha256_starts_stub("mbedtls_sha256_starts");
void mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224) {
  mbedtls_sha256_starts_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_sha256_update_stub("mbedtls_sha256_update");
void mbedtls_sha256_update(mbedtls_sha256_context *ctx, const unsigned char *input, size_t ilen) {
  mbedtls_sha256_update_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_sha256_finish_stub("mbedtls_sha256_finish");
void mbedtls_sha256_finish(mbedtls_sha256_context *ctx, unsigned char output[32]) {
  mbedtls_sha256_finish_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_ssl_get_verify_result_stub("mbedtls_ssl_get_verify_result");
uint32_t mbedtls_ssl_get_verify_result(const mbedtls_ssl_context *ssl) { 
  mbedtls_ssl_get_verify_result_stub.recordFunctionCall();
  return mbedtls_ssl_get_verify_result_stub.mock<uint32_t>("mbedtls_ssl_get_verify_result");
}

FunctionEmulator mbedtls_ssl_get_bytes_avail_stub("mbedtls_ssl_get_bytes_avail");
size_t mbedtls_ssl_get_bytes_avail(const mbedtls_ssl_context *ssl) { 
  mbedtls_ssl_get_bytes_avail_stub.recordFunctionCall();
  return mbedtls_ssl_get_bytes_avail_stub.mock<size_t>("mbedtls_ssl_get_bytes_avail");
}

FunctionEmulator mbedtls_ctr_drbg_seed_stub("mbedtls_ctr_drbg_seed");
int mbedtls_ctr_drbg_seed(mbedtls_ctr_drbg_context *ctx, int (*f_entropy)(void *, unsigned char *, size_t), void *p_entropy, const unsigned char *custom, size_t len) { 
  mbedtls_ctr_drbg_seed_stub.recordFunctionCall();
  return mbedtls_ctr_drbg_seed_stub.mock<int>("mbedtls_ctr_drbg_seed");
}

FunctionEmulator mbedtls_entropy_func_stub("mbedtls_entropy_func");
int mbedtls_entropy_func(void *data, unsigned char *output, size_t len) {
  mbedtls_entropy_func_stub.recordFunctionCall();
  return mbedtls_entropy_func_stub.mock<int>("mbedtls_entropy_func");
}

FunctionEmulator mbedtls_ssl_config_defaults_stub("mbedtls_ssl_config_defaults");
int mbedtls_ssl_config_defaults(mbedtls_ssl_config *conf, int endpoint, int transport, int preset) {
  mbedtls_ssl_config_defaults_stub.recordFunctionCall();
  return mbedtls_ssl_config_defaults_stub.mock<int>("mbedtls_ssl_config_defaults");
}

FunctionEmulator mbedtls_x509_crt_parse_stub("mbedtls_x509_crt_parse");
int mbedtls_x509_crt_parse(mbedtls_x509_crt *chain, const unsigned char *buf, size_t buflen) {
  mbedtls_x509_crt_parse_stub.recordFunctionCall();
  return mbedtls_x509_crt_parse_stub.mock<int>("mbedtls_x509_crt_parse");
}

FunctionEmulator mbedtls_ssl_conf_psk_stub("mbedtls_ssl_conf_psk");
int mbedtls_ssl_conf_psk(mbedtls_ssl_config *conf, const unsigned char *psk, size_t psk_len, const unsigned char *psk_identity, size_t psk_identity_len) {
  mbedtls_ssl_conf_psk_stub.recordFunctionCall();
  return mbedtls_ssl_conf_psk_stub.mock<int>("mbedtls_ssl_conf_psk");
}

FunctionEmulator mbedtls_pk_parse_key_stub("mbedtls_pk_parse_key");
int mbedtls_pk_parse_key(mbedtls_pk_context *pk, const unsigned char *key, size_t keylen, const unsigned char *pwd, size_t pwdlen) {
  mbedtls_pk_parse_key_stub.recordFunctionCall();
  return mbedtls_pk_parse_key_stub.mock<int>("mbedtls_pk_parse_key");
}

FunctionEmulator mbedtls_ssl_conf_own_cert_stub("mbedtls_ssl_conf_own_cert");
int mbedtls_ssl_conf_own_cert(mbedtls_ssl_config *conf, mbedtls_x509_crt *own_cert, mbedtls_pk_context *pk_key) {
  mbedtls_ssl_conf_own_cert_stub.recordFunctionCall();
  return mbedtls_ssl_conf_own_cert_stub.mock<int>("mbedtls_ssl_conf_own_cert");
}

FunctionEmulator mbedtls_ssl_set_hostname_stub("mbedtls_ssl_set_hostname");
int mbedtls_ssl_set_hostname(mbedtls_ssl_context *ssl, const char *hostname) {
  mbedtls_ssl_set_hostname_stub.recordFunctionCall();
  return mbedtls_ssl_set_hostname_stub.mock<int>("mbedtls_ssl_set_hostname");
}

FunctionEmulator mbedtls_ctr_drbg_random_stub("mbedtls_ctr_drbg_random");
int mbedtls_ctr_drbg_random(void *p_rng, unsigned char *output, size_t output_len) {
  mbedtls_ctr_drbg_random_stub.recordFunctionCall();
  return mbedtls_ctr_drbg_random_stub.mock<int>("mbedtls_ctr_drbg_random");
}

FunctionEmulator mbedtls_ssl_setup_stub("mbedtls_ssl_setup");
int mbedtls_ssl_setup(mbedtls_ssl_context *ssl, const mbedtls_ssl_config *conf) {
  mbedtls_ssl_setup_stub.recordFunctionCall();
  return mbedtls_ssl_setup_stub.mock<int>("mbedtls_ssl_setup");
}

FunctionEmulator mbedtls_ssl_handshake_stub("mbedtls_ssl_handshake");
int mbedtls_ssl_handshake(mbedtls_ssl_context *ssl) {
  mbedtls_ssl_handshake_stub.recordFunctionCall();
  return mbedtls_ssl_handshake_stub.mock<int>("mbedtls_ssl_handshake");
}

FunctionEmulator mbedtls_ssl_get_record_expansion_stub("mbedtls_ssl_get_record_expansion");
int mbedtls_ssl_get_record_expansion(const mbedtls_ssl_context *ssl) {
  mbedtls_ssl_get_record_expansion_stub.recordFunctionCall();
  return mbedtls_ssl_get_record_expansion_stub.mock<int>("mbedtls_ssl_get_record_expansion");
}

FunctionEmulator mbedtls_x509_crt_verify_info_stub("mbedtls_x509_crt_verify_info");
int mbedtls_x509_crt_verify_info(char *buf, size_t size, const char *prefix, uint32_t flags) {
  mbedtls_x509_crt_verify_info_stub.recordFunctionCall();
  return mbedtls_x509_crt_verify_info_stub.mock<int>("mbedtls_x509_crt_verify_info");
}

FunctionEmulator mbedtls_ssl_read_stub("mbedtls_ssl_read");
int mbedtls_ssl_read(mbedtls_ssl_context *ssl, unsigned char *buf, size_t len) {
  mbedtls_ssl_read_stub.recordFunctionCall();
  return mbedtls_ssl_read_stub.mock<int>("mbedtls_ssl_read");
}

FunctionEmulator mbedtls_ssl_write_stub("mbedtls_ssl_write");
int mbedtls_ssl_write(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len) {
  mbedtls_ssl_write_stub.recordFunctionCall();
  return mbedtls_ssl_write_stub.mock<int>("mbedtls_ssl_write");
}

FunctionEmulator mbedtls_ssl_get_version_stub("mbedtls_ssl_get_version");
const char *mbedtls_ssl_get_version(const mbedtls_ssl_context *ssl) {
  mbedtls_ssl_get_version_stub.recordFunctionCall();
  return mbedtls_ssl_get_version_stub.mock<const char*>("mbedtls_ssl_get_version");
}

FunctionEmulator mbedtls_ssl_get_ciphersuite_stub("mbedtls_ssl_get_ciphersuite");
const char *mbedtls_ssl_get_ciphersuite(const mbedtls_ssl_context *ssl) {
  mbedtls_ssl_get_ciphersuite_stub.recordFunctionCall();
  return mbedtls_ssl_get_ciphersuite_stub.mock<const char*>("mbedtls_ssl_get_ciphersuite");
}

FunctionEmulator mbedtls_ssl_conf_alpn_protocols_stub("mbedtls_ssl_conf_alpn_protocols");
int mbedtls_ssl_conf_alpn_protocols(mbedtls_ssl_config *conf, const char **protos) {
  mbedtls_ssl_conf_alpn_protocols_stub.recordFunctionCall();
  return mbedtls_ssl_conf_alpn_protocols_stub.mock<int>("mbedtls_ssl_conf_alpn_protocols");
}

FunctionEmulator mbedtls_pk_parse_public_key_stub("mbedtls_ssl_conf_alpn_protocols");
int mbedtls_pk_parse_public_key(mbedtls_pk_context *ctx, const unsigned char *key, size_t keylen) {
  mbedtls_pk_parse_public_key_stub.recordFunctionCall();
  return mbedtls_pk_parse_public_key_stub.mock<int>("mbedtls_pk_parse_key");
}

FunctionEmulator mbedtls_pk_can_do_stub("mbedtls_pk_can_do_stub");
int mbedtls_pk_can_do( const mbedtls_pk_context *ctx, mbedtls_pk_type_t type ) {
  mbedtls_pk_can_do_stub.recordFunctionCall();
  return mbedtls_pk_can_do_stub.mock<int>("mbedtls_pk_can_do");
}

FunctionEmulator mbedtls_ssl_conf_verify_stub("mbedtls_ssl_conf_verify");
void mbedtls_ssl_conf_verify(mbedtls_ssl_config *conf, int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *), void *p_vrfy) {
  mbedtls_ssl_conf_verify_stub.recordFunctionCall();
}

FunctionEmulator mbedtls_md_get_size_stub("mbedtls_md_get_size");
unsigned char mbedtls_md_get_size(const mbedtls_md_info_t *md_info) {
  mbedtls_md_get_size_stub.recordFunctionCall();
  return mbedtls_md_get_size_stub.mock<unsigned char>("mbedtls_md_get_size");
}

FunctionEmulator mbedtls_md_info_from_type_stub("mbedtls_md_info_from_type");
const mbedtls_md_info_t *mbedtls_md_info_from_type (mbedtls_md_type_t md_type) {
  mbedtls_md_info_from_type_stub.recordFunctionCall();
  return mbedtls_md_info_from_type_stub.mock<const mbedtls_md_info_t*>("mbedtls_md_info_from_type");
}

FunctionEmulator mbedtls_pk_verify_ext_stub("mbedtls_pk_verify_ext");
int mbedtls_pk_verify_ext(mbedtls_pk_type_t type, const void *options, mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, const unsigned char *sig, size_t sig_len) {
  mbedtls_pk_verify_ext_stub.recordFunctionCall();
  return mbedtls_pk_verify_ext_stub.mock<int>("mbedtls_pk_verify_ext");
}

FunctionEmulator mbedtls_md_stub("mbedtls_md");
int mbedtls_md(const mbedtls_md_info_t *md_info, unsigned char *p, size_t len, unsigned char hash[32]) {
  mbedtls_md_stub.recordFunctionCall();
  return mbedtls_md_stub.mock<int>("mbedtls_md");
}

void mbedtls_mock_reset_return_values() {
  mbedtls_ssl_get_peer_cert_stub.reset();
  mbedtls_ssl_init_stub.reset();
  mbedtls_ssl_config_init_stub.reset();
  mbedtls_entropy_init_stub.reset();
  mbedtls_ctr_drbg_init_stub.reset();
  mbedtls_x509_crt_init_stub.reset();
  mbedtls_ssl_conf_authmode_stub.reset();
  mbedtls_ssl_conf_ca_chain_stub.reset();
  mbedtls_pk_init_stub.reset();
  mbedtls_x509_crt_free_stub.reset();
  mbedtls_ssl_conf_rng_stub.reset();
  mbedtls_ssl_set_bio_stub.reset();
  mbedtls_ssl_conf_read_timeout_stub.reset();
  mbedtls_pk_free_stub.reset();
  mbedtls_ssl_free_stub.reset();
  mbedtls_ssl_config_free_stub.reset();
  mbedtls_ctr_drbg_free_stub.reset();
  mbedtls_entropy_free_stub.reset();
  mbedtls_sha256_init_stub.reset();
  mbedtls_sha256_starts_stub.reset();
  mbedtls_sha256_update_stub.reset();
  mbedtls_sha256_finish_stub.reset();
  mbedtls_ssl_get_verify_result_stub.reset();
  mbedtls_ssl_get_bytes_avail_stub.reset();
  mbedtls_ctr_drbg_seed_stub.reset();
  mbedtls_entropy_func_stub.reset();
  mbedtls_ssl_config_defaults_stub.reset();
  mbedtls_x509_crt_parse_stub.reset();
  mbedtls_ssl_conf_psk_stub.reset();
  mbedtls_pk_parse_key_stub.reset();
  mbedtls_ssl_conf_own_cert_stub.reset();
  mbedtls_ssl_set_hostname_stub.reset();
  mbedtls_ctr_drbg_random_stub.reset();
  mbedtls_ssl_setup_stub.reset();
  mbedtls_ssl_handshake_stub.reset();
  mbedtls_ssl_get_record_expansion_stub.reset();
  mbedtls_x509_crt_verify_info_stub.reset();
  mbedtls_ssl_read_stub.reset();
  mbedtls_ssl_write_stub.reset();
  mbedtls_ssl_get_version_stub.reset();
  mbedtls_ssl_get_ciphersuite_stub.reset();
  mbedtls_pk_parse_public_key_stub.reset();
  mbedtls_pk_can_do_stub.reset();
  mbedtls_ssl_conf_verify_stub.reset();
  mbedtls_md_get_size_stub.reset();
  mbedtls_md_info_from_type_stub.reset();
}

#endif // MBEDTLS_MOCK_H