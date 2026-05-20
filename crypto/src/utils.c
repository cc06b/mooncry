#include "financial_crypto.h"
#include <stdlib.h>
#include <time.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

CryptoResult generate_random_bytes(uint8_t* buffer, size_t length) {
    if (!buffer) {
        return CRYPTO_ERROR_NULL_POINTER;
    }

#ifdef _WIN32
    HCRYPTPROV h_prov;
    if (!CryptAcquireContext(&h_prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return CRYPTO_ERROR_MEMORY;
    }

    if (!CryptGenRandom(h_prov, (DWORD)length, buffer)) {
        CryptReleaseContext(h_prov, 0);
        return CRYPTO_ERROR_MEMORY;
    }

    CryptReleaseContext(h_prov, 0);
    return CRYPTO_SUCCESS;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        srand((unsigned int)time(NULL));
        size_t i;
        for (i = 0; i < length; i++) {
            buffer[i] = (uint8_t)(rand() & 0xff);
        }
        return CRYPTO_SUCCESS;
    }

    ssize_t read_bytes = read(fd, buffer, length);
    close(fd);

    if (read_bytes != (ssize_t)length) {
        srand((unsigned int)time(NULL));
        size_t i;
        for (i = 0; i < length; i++) {
            buffer[i] = (uint8_t)(rand() & 0xff);
        }
    }

    return CRYPTO_SUCCESS;
#endif
}

const char* crypto_result_to_string(CryptoResult result) {
    switch (result) {
        case CRYPTO_SUCCESS:
            return "Success";
        case CRYPTO_ERROR_NULL_POINTER:
            return "Null pointer error";
        case CRYPTO_ERROR_INVALID_LENGTH:
            return "Invalid length";
        case CRYPTO_ERROR_MEMORY:
            return "Memory error";
        case CRYPTO_ERROR_ENCRYPT:
            return "Encryption error";
        case CRYPTO_ERROR_DECRYPT:
            return "Decryption error";
        case CRYPTO_ERROR_INVALID_KEY:
            return "Invalid key";
        default:
            return "Unknown error";
    }
}
