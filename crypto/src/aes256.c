#include "financial_crypto.h"
#include <string.h>
#include <stdlib.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE_256 32
#define AES_ROUNDS_256 14

typedef struct {
    uint32_t round_keys[60];
    int rounds;
} AES256_CTX;

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

#define ROTWORD(x) (((x) >> 24) | ((x) << 8))
#define SUBWORD(x) ((uint32_t)sbox[(x) >> 24] << 24 | \
                    (uint32_t)sbox[((x) >> 16) & 0xff] << 16 | \
                    (uint32_t)sbox[((x) >> 8) & 0xff] << 8 | \
                    (uint32_t)sbox[(x) & 0xff])

static void aes256_key_expansion(AES256_CTX* ctx, const uint8_t* key) {
    int i;
    uint32_t temp;

    for (i = 0; i < 8; i++) {
        ctx->round_keys[i] = ((uint32_t)key[4 * i] << 24) |
                            ((uint32_t)key[4 * i + 1] << 16) |
                            ((uint32_t)key[4 * i + 2] << 8) |
                            ((uint32_t)key[4 * i + 3]);
    }

    for (i = 8; i < 60; i++) {
        temp = ctx->round_keys[i - 1];
        if (i % 8 == 0) {
            temp = SUBWORD(ROTWORD(temp)) ^ ((uint32_t)rcon[i / 8] << 24);
        } else if (i % 8 == 4) {
            temp = SUBWORD(temp);
        }
        ctx->round_keys[i] = ctx->round_keys[i - 8] ^ temp;
    }

    ctx->rounds = AES_ROUNDS_256;
}

static void aes256_add_round_key(uint8_t* state, const uint32_t* round_key) {
    int i;
    for (i = 0; i < 4; i++) {
        state[4 * i] ^= (uint8_t)(round_key[i] >> 24);
        state[4 * i + 1] ^= (uint8_t)(round_key[i] >> 16);
        state[4 * i + 2] ^= (uint8_t)(round_key[i] >> 8);
        state[4 * i + 3] ^= (uint8_t)(round_key[i]);
    }
}

static void aes256_sub_bytes(uint8_t* state) {
    int i;
    for (i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

static void aes256_inv_sub_bytes(uint8_t* state) {
    int i;
    for (i = 0; i < 16; i++) {
        state[i] = inv_sbox[state[i]];
    }
}

static void aes256_shift_rows(uint8_t* state) {
    uint8_t temp;

    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

static void aes256_inv_shift_rows(uint8_t* state) {
    uint8_t temp;

    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    temp = state[10];
    state[10] = state[2];
    state[2] = temp;
    temp = state[14];
    state[14] = state[6];
    state[6] = temp;

    temp = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = state[3];
    state[3] = temp;
}

static uint8_t gf_mult(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t hi_bit_set;
    int i;

    for (i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x1b;
        }
        b >>= 1;
    }

    return p;
}

static void aes256_mix_columns(uint8_t* state) {
    uint8_t temp[16];
    int i;

    for (i = 0; i < 4; i++) {
        temp[4 * i] = gf_mult(2, state[4 * i]) ^ gf_mult(3, state[4 * i + 1]) ^ 
                      state[4 * i + 2] ^ state[4 * i + 3];
        temp[4 * i + 1] = state[4 * i] ^ gf_mult(2, state[4 * i + 1]) ^ 
                          gf_mult(3, state[4 * i + 2]) ^ state[4 * i + 3];
        temp[4 * i + 2] = state[4 * i] ^ state[4 * i + 1] ^ 
                          gf_mult(2, state[4 * i + 2]) ^ gf_mult(3, state[4 * i + 3]);
        temp[4 * i + 3] = gf_mult(3, state[4 * i]) ^ state[4 * i + 1] ^ 
                          state[4 * i + 2] ^ gf_mult(2, state[4 * i + 3]);
    }

    memcpy(state, temp, 16);
}

static void aes256_inv_mix_columns(uint8_t* state) {
    uint8_t temp[16];
    int i;

    for (i = 0; i < 4; i++) {
        temp[4 * i] = gf_mult(0x0e, state[4 * i]) ^ gf_mult(0x0b, state[4 * i + 1]) ^ 
                      gf_mult(0x0d, state[4 * i + 2]) ^ gf_mult(0x09, state[4 * i + 3]);
        temp[4 * i + 1] = gf_mult(0x09, state[4 * i]) ^ gf_mult(0x0e, state[4 * i + 1]) ^ 
                          gf_mult(0x0b, state[4 * i + 2]) ^ gf_mult(0x0d, state[4 * i + 3]);
        temp[4 * i + 2] = gf_mult(0x0d, state[4 * i]) ^ gf_mult(0x09, state[4 * i + 1]) ^ 
                          gf_mult(0x0e, state[4 * i + 2]) ^ gf_mult(0x0b, state[4 * i + 3]);
        temp[4 * i + 3] = gf_mult(0x0b, state[4 * i]) ^ gf_mult(0x0d, state[4 * i + 1]) ^ 
                          gf_mult(0x09, state[4 * i + 2]) ^ gf_mult(0x0e, state[4 * i + 3]);
    }

    memcpy(state, temp, 16);
}

static void aes256_encrypt_block(AES256_CTX* ctx, const uint8_t* input, uint8_t* output) {
    uint8_t state[16];
    int round;

    memcpy(state, input, 16);
    aes256_add_round_key(state, &ctx->round_keys[0]);

    for (round = 1; round < ctx->rounds; round++) {
        aes256_sub_bytes(state);
        aes256_shift_rows(state);
        aes256_mix_columns(state);
        aes256_add_round_key(state, &ctx->round_keys[4 * round]);
    }

    aes256_sub_bytes(state);
    aes256_shift_rows(state);
    aes256_add_round_key(state, &ctx->round_keys[4 * ctx->rounds]);

    memcpy(output, state, 16);
}

static void aes256_decrypt_block(AES256_CTX* ctx, const uint8_t* input, uint8_t* output) {
    uint8_t state[16];
    int round;

    memcpy(state, input, 16);
    aes256_add_round_key(state, &ctx->round_keys[4 * ctx->rounds]);

    for (round = ctx->rounds - 1; round > 0; round--) {
        aes256_inv_shift_rows(state);
        aes256_inv_sub_bytes(state);
        aes256_add_round_key(state, &ctx->round_keys[4 * round]);
        aes256_inv_mix_columns(state);
    }

    aes256_inv_shift_rows(state);
    aes256_inv_sub_bytes(state);
    aes256_add_round_key(state, &ctx->round_keys[0]);

    memcpy(output, state, 16);
}

static void xor_blocks(uint8_t* a, const uint8_t* b, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        a[i] ^= b[i];
    }
}

CryptoResult aes_256_cbc_encrypt(const uint8_t* key, size_t key_len,
                                 const uint8_t* iv, size_t iv_len,
                                 const uint8_t* plaintext, size_t plaintext_len,
                                 uint8_t* ciphertext, size_t* ciphertext_len) {
    if (!key || !iv || !plaintext || !ciphertext || !ciphertext_len) {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    if (key_len != AES_KEY_SIZE_256) {
        return CRYPTO_ERROR_INVALID_KEY;
    }

    if (iv_len != AES_BLOCK_SIZE) {
        return CRYPTO_ERROR_INVALID_LENGTH;
    }

    size_t padding = AES_BLOCK_SIZE - (plaintext_len % AES_BLOCK_SIZE);
    size_t total_len = plaintext_len + padding;

    if (*ciphertext_len < total_len) {
        *ciphertext_len = total_len;
        return CRYPTO_ERROR_INVALID_LENGTH;
    }

    AES256_CTX ctx;
    aes256_key_expansion(&ctx, key);

    uint8_t prev_block[AES_BLOCK_SIZE];
    memcpy(prev_block, iv, AES_BLOCK_SIZE);

    uint8_t* padded_plaintext = (uint8_t*)malloc(total_len);
    if (!padded_plaintext) {
        return CRYPTO_ERROR_MEMORY;
    }

    memcpy(padded_plaintext, plaintext, plaintext_len);
    memset(padded_plaintext + plaintext_len, (uint8_t)padding, padding);

    size_t i;
    for (i = 0; i < total_len; i += AES_BLOCK_SIZE) {
        xor_blocks(&padded_plaintext[i], prev_block, AES_BLOCK_SIZE);
        aes256_encrypt_block(&ctx, &padded_plaintext[i], &ciphertext[i]);
        memcpy(prev_block, &ciphertext[i], AES_BLOCK_SIZE);
    }

    free(padded_plaintext);
    *ciphertext_len = total_len;

    return CRYPTO_SUCCESS;
}

CryptoResult aes_256_cbc_decrypt(const uint8_t* key, size_t key_len,
                                 const uint8_t* iv, size_t iv_len,
                                 const uint8_t* ciphertext, size_t ciphertext_len,
                                 uint8_t* plaintext, size_t* plaintext_len) {
    if (!key || !iv || !ciphertext || !plaintext || !plaintext_len) {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    if (key_len != AES_KEY_SIZE_256) {
        return CRYPTO_ERROR_INVALID_KEY;
    }

    if (iv_len != AES_BLOCK_SIZE) {
        return CRYPTO_ERROR_INVALID_LENGTH;
    }

    if (ciphertext_len % AES_BLOCK_SIZE != 0) {
        return CRYPTO_ERROR_INVALID_LENGTH;
    }

    if (*plaintext_len < ciphertext_len) {
        *plaintext_len = ciphertext_len;
        return CRYPTO_ERROR_INVALID_LENGTH;
    }

    AES256_CTX ctx;
    aes256_key_expansion(&ctx, key);

    uint8_t prev_block[AES_BLOCK_SIZE];
    memcpy(prev_block, iv, AES_BLOCK_SIZE);

    uint8_t temp_block[AES_BLOCK_SIZE];
    size_t i;
    for (i = 0; i < ciphertext_len; i += AES_BLOCK_SIZE) {
        memcpy(temp_block, &ciphertext[i], AES_BLOCK_SIZE);
        aes256_decrypt_block(&ctx, &ciphertext[i], &plaintext[i]);
        xor_blocks(&plaintext[i], prev_block, AES_BLOCK_SIZE);
        memcpy(prev_block, temp_block, AES_BLOCK_SIZE);
    }

    uint8_t padding = plaintext[ciphertext_len - 1];
    if (padding < 1 || padding > AES_BLOCK_SIZE) {
        return CRYPTO_ERROR_DECRYPT;
    }

    *plaintext_len = ciphertext_len - padding;

    return CRYPTO_SUCCESS;
}
