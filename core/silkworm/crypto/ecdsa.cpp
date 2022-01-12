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

#include <ethash/hash_types.hpp>
#include <ethash/keccak.hpp>
#include <secp256k1_recovery.h>

namespace silkworm::ecdsa {

intx::uint256 y_parity_and_chain_id_to_v(bool odd, const std::optional<intx::uint256>& chain_id) noexcept {
    if (chain_id.has_value()) {
        return chain_id.value() * 2 + 35 + odd;
    } else {
        return odd ? 28 : 27;
    }
}

std::optional<YParityAndChainId> v_to_y_parity_and_chain_id(const intx::uint256& v) noexcept {
    YParityAndChainId res{};
    if (v == 27 || v == 28) {
        // pre EIP-155
        res.odd = v == 28;
        res.chain_id = std::nullopt;
    } else if (v < 35) {
        // EIP-155 implies v >= 35
        return std::nullopt;
    } else {
        // https://eips.ethereum.org/EIPS/eip-155
        // Find chain_id and y_parity ∈ {0, 1} such that
        // v = chain_id * 2 + 35 + y_parity
        intx::uint256 w{v - 35};
        res.odd = static_cast<uint64_t>(w) % 2;
        res.chain_id.emplace(w >> 1);  // w / 2
    }
    return res;
}

secp256k1_context* create_context(uint32_t flags) { return secp256k1_context_create(flags); }

bool is_valid_signature(const intx::uint256& r, const intx::uint256& s, bool homestead) noexcept {
    if (!r || !s) {
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

std::optional<Bytes> recover(ByteView message, ByteView signature, bool odd_y_parity,
                             secp256k1_context* context) noexcept {
    static secp256k1_context* static_context{create_context()};
    if (!context) {
        context = static_context;
    }

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

std::optional<evmc::address> public_key_to_address(const Bytes& public_key) noexcept {
    if (public_key.length() != 65 || public_key[0] != 4u) {
        return std::nullopt;
    }
    // Ignore first byte of public key
    const auto key_hash{ethash::keccak256(public_key.data() + 1, 64)};
    return evmc::address(*reinterpret_cast<const evmc_address*>(&key_hash.bytes[12]));
}

std::optional<evmc::address> recover_address(ByteView message, ByteView signature, bool odd_y_parity,
                                             secp256k1_context* context) noexcept {
    const auto recovered_public_key{recover(message, signature, odd_y_parity, context)};
    return public_key_to_address(recovered_public_key.value_or(Bytes{}));
}

}  // namespace silkworm::ecdsa
