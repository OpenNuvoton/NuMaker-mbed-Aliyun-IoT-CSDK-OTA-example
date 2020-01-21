#ifndef MBEDTLS_USER_CONFIG_H
#define MBEDTLS_USER_CONFIG_H


/* Support RFC 6066 max_fragment_length extension
 *
 * Reduce IO buffer to save RAM and set default to 4KB. Buffers can be smaller if MFL is enabled.
 * Buffer length must be sufficient to hold each handshake message in unfragmented form.
 * The largest message is the Certificate message and size is selected based on that.
 *
 * As of this writing, it seems that Aliyun (Alibaba Cloud) IoT Platform doesn't support
 * RFC 6066 max_fragment_length extension yet. But still enable it for reducing RAM footprint
 * largely when it gets supported.
 */
#if (CONFIG_MBEDTLS_MFL_CODE == 1)
    #define MBEDTLS_SSL_MAX_CONTENT_LEN 1024
#elif (CONFIG_MBEDTLS_MFL_CODE == 2)
    #define MBEDTLS_SSL_MAX_CONTENT_LEN 1024
#else
    #define MBEDTLS_SSL_MAX_CONTENT_LEN 4096
#endif

#ifndef MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_MEMORY
#endif

// define to save 8KB RAM at the expense of ROM
#ifndef MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_AES_ROM_TABLES
#endif

#ifndef MBEDTLS_CIPHER_PADDING_ZEROS
#define MBEDTLS_CIPHER_PADDING_ZEROS
#endif

#undef MBEDTLS_ECP_DP_SECP192R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP224R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP384R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP521R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP192K1_ENABLED
#undef MBEDTLS_ECP_DP_SECP224K1_ENABLED
#undef MBEDTLS_ECP_DP_SECP256K1_ENABLED
#undef MBEDTLS_ECP_DP_BP256R1_ENABLED
#undef MBEDTLS_ECP_DP_BP384R1_ENABLED
#undef MBEDTLS_ECP_DP_BP512R1_ENABLED
#undef MBEDTLS_ECP_DP_CURVE25519_ENABLED
#undef MBEDTLS_ECP_DP_SECP256R1_ENABLED


#undef MBEDTLS_ECP_NIST_OPTIM
#undef MBEDTLS_ECDSA_DETERMINISTIC
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED

// Required by aliyun (alibaba cloud)
#define MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED

#undef MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

#ifndef MBEDTLS_GENPRIME
#define MBEDTLS_GENPRIME
#endif


#undef MBEDTLS_PK_RSA_ALT_SUPPORT

// Remove self-test and save 11KB of ROM
#undef MBEDTLS_SELF_TEST

#undef MBEDTLS_SSL_ENCRYPT_THEN_MAC
#undef MBEDTLS_SSL_EXTENDED_MASTER_SECRET


#undef MBEDTLS_SSL_ALPN
#undef MBEDTLS_SSL_DTLS_ANTI_REPLAY
#undef MBEDTLS_SSL_DTLS_BADMAC_LIMIT
//#undef MBEDTLS_SSL_EXPORT_KEYS
#undef MBEDTLS_SSL_SERVER_NAME_INDICATION
#undef MBEDTLS_ASN1_WRITE_C
#undef MBEDTLS_CCM_C
#undef MBEDTLS_CHACHA20_C
#undef MBEDTLS_CHACHAPOLY_C

// Required by mbed DeviceKey
//#undef MBEDTLS_CMAC_C

#undef MBEDTLS_ECDH_C
#undef MBEDTLS_ECDSA_C
#undef MBEDTLS_ECP_C
#undef MBEDTLS_GCM_C
#undef MBEDTLS_HKDF_C
#undef MBEDTLS_HMAC_DRBG_C

// We provide mbedtls_net_xxx_alt for mbed port
#undef MBEDTLS_NET_C

#undef MBEDTLS_PK_WRITE_C
#undef MBEDTLS_POLY1305_C

// Required by aliyun (alibaba cloud)
#ifndef MBEDTLS_SHA1_C
#define MBEDTLS_SHA1_C
#endif

// Required by aliyun (alibaba cloud)
#ifndef MBEDTLS_CIPHER_MODE_CFB
#define MBEDTLS_CIPHER_MODE_CFB
#endif

#undef MBEDTLS_SSL_TICKET_C
#undef MBEDTLS_SSL_SRV_C

// We provide mbedtls_timing_xxx_alt for mbed port
#undef MBEDTLS_TIMING_C

//#define MBEDTLS_X509_CRL_PARSE_C

// Remove error messages, save 10KB of ROM
#undef MBEDTLS_ERROR_C

// Reduces ROM size by 30 kB
#undef MBEDTLS_ERROR_STRERROR_DUMMY


#endif  /* mbedtls_user_config.h */
