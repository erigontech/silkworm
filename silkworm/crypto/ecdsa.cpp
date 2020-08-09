/*
   Copyright 2020 The Silkworm Authors

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

static secp256k1_context* kDefaultContext{
    secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)};

bool inputs_are_valid(const intx::uint256& v, const intx::uint256& r, const intx::uint256& s,
                      bool homestead) {
  if (r == 0 || s == 0 || v > 1) return false;
  if (homestead && s > kSecp256k1n_div2) return false;
  return r < kSecp256k1n && s < kSecp256k1n;
}

bool is_valid_signature(const intx::uint256& v, const intx::uint256& r, const intx::uint256& s,
                        bool homestead, uint64_t chain_id) {

    if (!is_valid_signature_recovery(get_signature_recovery(v, chain_id)))
    {
        return false;
    }

    if (r == 0 || r > kSecp256k1n || s == 0 || s > homestead ? kSecp256k1n_div2 : kSecp256k1n)
    {
        return false;
    }

    return true;
}

intx::uint256 get_signature_recovery(const intx::uint256& v, uint64_t chain_id) {
  return chain_id ? v - (2 * chain_id + 35) : v - 27;
}

bool is_valid_signature_recovery(intx::uint256 recovery) { return recovery == 0 || recovery == 1; }

std::optional<Bytes> recover(ByteView message, ByteView signature, uint8_t recovery_id) {
  if (message.length() != 32) return {};
  if (signature.length() != 64) return {};

  secp256k1_ecdsa_recoverable_signature sig;
  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(kDefaultContext, &sig, &signature[0],
                                                           recovery_id)) {
    return {};
  }

  secp256k1_pubkey pub_key;
  if (!secp256k1_ecdsa_recover(kDefaultContext, &pub_key, &sig, &message[0])) {
    return {};
  }

  size_t kOutLen{65};
  Bytes out(kOutLen, '\0');
  secp256k1_ec_pubkey_serialize(kDefaultContext, &out[0], &kOutLen, &pub_key,
                                SECP256K1_EC_UNCOMPRESSED);
  return out;
}
}  // namespace silkworm::ecdsa
