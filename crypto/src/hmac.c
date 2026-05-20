#include "financial_crypto.h"
#include <string.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

CryptoResult hmac_sha256(const uint8_t* key, size_t key_len,
                         const uint8_t* data, size_t data_len,
                         uint8_t* output, size_t* output_len) {
    if (!key || !data || !output || !output_len) {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    if (*output_len < SHA256_DIGEST_SIZE) {
        *output_len = SHA256_DIGEST_SIZE;
        return CRYPTO_ERROR_INVALID_LENGTH;
    }

    uint8_t k_ipad[SHA256_BLOCK_SIZE];
    uint8_t k_opad[SHA256_BLOCK_SIZE];
    uint8_t temp_key[SHA256_DIGEST_SIZE];
    uint8_t inner_hash[SHA256_DIGEST_SIZE];
    size_t temp_len;
    int i;

    if (key_len > SHA256_BLOCK_SIZE) {
        temp_len = SHA256_DIGEST_SIZE;
        CryptoResult result = sha256_hash(key, key_len, temp_key, &temp_len);
        if (result != CRYPTO_SUCCESS) {
            return result;
        }
        key = temp_key;
        key_len = temp_len;
    }

    memset(k_ipad, 0x36, SHA256_BLOCK_SIZE);
    memset(k_opad, 0x5c, SHA256_BLOCK_SIZE);

    for (i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    uint8_t* inner_data = (uint8_t*)malloc(SHA256_BLOCK_SIZE + data_len);
    if (!inner_data) {
        return CRYPTO_ERROR_MEMORY;
    }

    memcpy(inner_data, k_ipad, SHA256_BLOCK_SIZE);
    memcpy(inner_data + SHA256_BLOCK_SIZE, data, data_len);

    temp_len = SHA256_DIGEST_SIZE;
    CryptoResult result = sha256_hash(inner_data, SHA256_BLOCK_SIZE + data_len, inner_hash, &temp_len);
    free(inner_data);

    if (result != CRYPTO_SUCCESS) {
        return result;
    }

    uint8_t* outer_data = (uint8_t*)malloc(SHA256_BLOCK_SIZE + SHA256_DIGEST_SIZE);
    if (!outer_data) {
        return CRYPTO_ERROR_MEMORY;
    }

    memcpy(outer_data, k_opad, SHA256_BLOCK_SIZE);
    memcpy(outer_data + SHA256_BLOCK_SIZE, inner_hash, SHA256_DIGEST_SIZE);

    temp_len = SHA256_DIGEST_SIZE;
    result = sha256_hash(outer_data, SHA256_BLOCK_SIZE + SHA256_DIGEST_SIZE, output, &temp_len);
    free(outer_data);

    if (result == CRYPTO_SUCCESS) {
        *output_len = SHA256_DIGEST_SIZE;
    }

    return result;
}
