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

#include "common/util.hpp"

namespace silkworm::ecdsa {

static secp256k1_context* kDefaultContext{
    secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)};

// TODO[Homestead] stricter checks
bool inputs_are_valid(const intx::uint256& v, const intx::uint256& r, const intx::uint256& s) {
  if (r == 0 || s == 0 || v > 1) return false;
  return r < kSecp256k1n && s < kSecp256k1n;
}

std::optional<std::string> recover(std::string_view message, std::string_view signature,
                                   uint8_t recovery_id) {
  if (message.length() != 32) return {};
  if (signature.length() != 64) return {};

  secp256k1_ecdsa_recoverable_signature sig;
  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
          kDefaultContext, &sig, byte_ptr_cast(&signature[0]), recovery_id)) {
    return {};
  }

  secp256k1_pubkey pub_key;
  if (!secp256k1_ecdsa_recover(kDefaultContext, &pub_key, &sig, byte_ptr_cast(&message[0]))) {
    return {};
  }

  size_t kOutLen{65};
  std::string out(kOutLen, '\0');
  secp256k1_ec_pubkey_serialize(kDefaultContext, byte_ptr_cast(&out[0]), &kOutLen, &pub_key,
                                SECP256K1_EC_UNCOMPRESSED);
  return out;
}
}  // namespace silkworm::ecdsa
