/*
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "hmac.hpp"

#include <gsl/util>
#include <openssl/hmac.h>

namespace silkworm::sentry::rlpx::crypto {

Bytes hmac(ByteView key, ByteView data1, ByteView data2, ByteView data3) {
    assert(key.size() == 32);

    HMAC_CTX* ctx = HMAC_CTX_new();
    auto _ = gsl::finally([ctx] { HMAC_CTX_free(ctx); });

    int ok = HMAC_Init_ex(ctx, key.data(), static_cast<int>(key.size()), EVP_sha256(), nullptr);
    if (!ok)
        throw std::runtime_error("Failed to init HMAC");

    HMAC_Update(ctx, data1.data(), data1.size());
    HMAC_Update(ctx, data2.data(), data2.size());
    HMAC_Update(ctx, data3.data(), data3.size());

    Bytes hash(HMAC_size(ctx), 0);
    HMAC_Final(ctx, hash.data(), nullptr);

    return hash;
}

}  // namespace silkworm::sentry::rlpx::crypto
