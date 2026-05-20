#ifndef FINANCIAL_CRYPTO_H
#define FINANCIAL_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
    #ifdef CRYPTO_EXPORTS
        #define CRYPTO_API __declspec(dllexport)
    #else
        #define CRYPTO_API __declspec(dllimport)
    #endif
#else
    #define CRYPTO_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CRYPTO_SUCCESS = 0,
    CRYPTO_ERROR_NULL_POINTER = -1,
    CRYPTO_ERROR_INVALID_LENGTH = -2,
    CRYPTO_ERROR_MEMORY = -3,
    CRYPTO_ERROR_ENCRYPT = -4,
    CRYPTO_ERROR_DECRYPT = -5,
    CRYPTO_ERROR_INVALID_KEY = -6
} CryptoResult;

CRYPTO_API CryptoResult sha256_hash(const uint8_t* data, size_t data_len, 
                                    uint8_t* output, size_t* output_len);

CRYPTO_API CryptoResult hmac_sha256(const uint8_t* key, size_t key_len,
                                     const uint8_t* data, size_t data_len,
                                     uint8_t* output, size_t* output_len);

CRYPTO_API CryptoResult aes_256_cbc_encrypt(const uint8_t* key, size_t key_len,
                                             const uint8_t* iv, size_t iv_len,
                                             const uint8_t* plaintext, size_t plaintext_len,
                                             uint8_t* ciphertext, size_t* ciphertext_len);

CRYPTO_API CryptoResult aes_256_cbc_decrypt(const uint8_t* key, size_t key_len,
                                             const uint8_t* iv, size_t iv_len,
                                             const uint8_t* ciphertext, size_t ciphertext_len,
                                             uint8_t* plaintext, size_t* plaintext_len);

CRYPTO_API CryptoResult generate_random_bytes(uint8_t* buffer, size_t length);

CRYPTO_API const char* crypto_result_to_string(CryptoResult result);

#ifdef __cplusplus
}
#endif

#endif
