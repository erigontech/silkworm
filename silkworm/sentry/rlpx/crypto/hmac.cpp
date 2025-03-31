// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "hmac.hpp"

#include <stdexcept>

#include <gsl/util>
#include <openssl/hmac.h>

namespace silkworm::sentry::rlpx::crypto {

#ifdef _WIN32
#pragma warning(disable : 4996)
#else
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

Bytes hmac(ByteView key, ByteView data1, ByteView data2, ByteView data3) {
    SILKWORM_ASSERT(key.size() == 32);

    HMAC_CTX* ctx = HMAC_CTX_new();
    [[maybe_unused]] auto _ = gsl::finally([ctx] { HMAC_CTX_free(ctx); });

    int ok = HMAC_Init_ex(ctx, key.data(), static_cast<int>(key.size()), EVP_sha256(), nullptr);
    if (!ok)
        throw std::runtime_error("rlpx::crypto::hmac: Failed to init HMAC");

    HMAC_Update(ctx, data1.data(), data1.size());
    HMAC_Update(ctx, data2.data(), data2.size());
    HMAC_Update(ctx, data3.data(), data3.size());

    Bytes hash(HMAC_size(ctx), 0);
    HMAC_Final(ctx, hash.data(), nullptr);

    return hash;
}

#pragma GCC diagnostic pop

}  // namespace silkworm::sentry::rlpx::crypto
