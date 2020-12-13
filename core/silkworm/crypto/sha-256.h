#ifndef SILKWORM_CRYPTO_SHA_256_H_
#define SILKWORM_CRYPTO_SHA_256_H_

#if defined(__cplusplus)
extern "C" {
#endif

void calc_sha_256(uint8_t hash[32], const void *input, size_t len);

#if defined(__cplusplus)
}
#endif

#endif  // SILKWORM_CRYPTO_SHA_256_H_
