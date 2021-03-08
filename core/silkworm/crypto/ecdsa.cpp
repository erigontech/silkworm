/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "ecdsa.hpp"

#include <secp256k1_recovery.h>

#include <silkworm/common/util.hpp>

namespace silkworm::ecdsa {

intx::uint256 y_parity_and_chain_id_to_v(bool odd, const std::optional<intx::uint256>& chain_id) {
    if (chain_id) {
        return *chain_id * 2 + 35 + odd;
    } else {
        return odd ? 28 : 27;
    }
}

YParityAndChainId v_to_y_parity_and_chain_id(const intx::uint256& v) {
    YParityAndChainId res{};
    if (v == 27 || v == 28) {
        // pre EIP-155
        res.odd = v == 28;
        res.chain_id = std::nullopt;
    } else {
        // https://eips.ethereum.org/EIPS/eip-155
        // Find chain_id and y_parity ∈ {0, 1} such that
        // v = chain_id * 2 + 35 + y_parity
        intx::uint256 w{v - 35};
        intx::uint256 chain_id{w >> 1};  // w / 2
        res.odd = static_cast<uint64_t>(w) % 2;
        res.chain_id = chain_id;
    }
    return res;
}

bool is_valid_signature(const intx::uint256& r, const intx::uint256& s, bool homestead) {
    if (r == 0 || s == 0) {
        return false;
    }
    if (r >= kSecp256k1n && s >= kSecp256k1n) {
        return false;
    }
    // https://eips.ethereum.org/EIPS/eip-2
    if (homestead && s > kSecp256k1Halfn) {
        return false;
    }
    return true;
}

std::optional<Bytes> recover(ByteView message, ByteView signature, bool odd_y_parity) {
    static secp256k1_context* context{secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)};

    if (message.length() != 32 || signature.length() != 64) {
        return std::nullopt;
    }

    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(context, &sig, &signature[0], odd_y_parity)) {
        return std::nullopt;
    }

    secp256k1_pubkey pub_key;
    if (!secp256k1_ecdsa_recover(context, &pub_key, &sig, &message[0])) {
        return std::nullopt;
    }

    size_t kOutLen{65};
    Bytes out(kOutLen, '\0');
    secp256k1_ec_pubkey_serialize(context, &out[0], &kOutLen, &pub_key, SECP256K1_EC_UNCOMPRESSED);
    return out;
}

}  // namespace silkworm::ecdsa
