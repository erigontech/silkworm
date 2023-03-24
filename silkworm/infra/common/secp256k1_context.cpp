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

#include "secp256k1_context.hpp"

namespace silkworm {

const size_t SecP256K1Context::kPublicKeySizeCompressed = 33;
const size_t SecP256K1Context::kPublicKeySizeUncompressed = 65;

Bytes SecP256K1Context::serialize_public_key(const secp256k1_pubkey* public_key, bool is_compressed) const {
    size_t data_size = is_compressed ? kPublicKeySizeCompressed : kPublicKeySizeUncompressed;
    Bytes data(data_size, 0);
    unsigned int flags = is_compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
    secp256k1_ec_pubkey_serialize(context_, data.data(), &data_size, public_key, flags);
    data.resize(data_size);
    return data;
}

unsigned int SecP256K1Context::flags(bool allow_verify, bool allow_sign) {
    unsigned int value = SECP256K1_CONTEXT_NONE;
    if (allow_verify) {
        value |= SECP256K1_CONTEXT_VERIFY;
    }
    if (allow_sign) {
        value |= SECP256K1_CONTEXT_SIGN;
    }
    return value;
}

}  // namespace silkworm
