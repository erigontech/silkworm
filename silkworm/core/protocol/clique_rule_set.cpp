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

#include "clique_rule_set.hpp"

#include <silkworm/core/crypto/ecdsa.h>

#include "param.hpp"

namespace silkworm::protocol {

ValidationResult CliqueRuleSet::validate_seal(const BlockHeader&) {
    return ValidationResult::kOk;
}

static evmc::address ecrecover(const BlockHeader& header) {
    evmc::address beneficiary = evmc::address{};

    evmc::bytes32 seal_hash = header.hash(false, true);
    ByteView signature{&header.extra_data[header.extra_data.length() - kExtraSealSize], kExtraSealSize - 1};
    uint8_t recovery_id{header.extra_data[header.extra_data.length() - 1]};

    static secp256k1_context* context{secp256k1_context_create(SILKWORM_SECP256K1_CONTEXT_FLAGS)};
    if (!silkworm_recover_address(beneficiary.bytes, seal_hash.bytes, signature.data(), recovery_id, context)) {
        return header.beneficiary;
    }
    return beneficiary;
}

evmc::address CliqueRuleSet::get_beneficiary(const BlockHeader& header) {
    if (header.extra_data.length() < kExtraSealSize) {
        return BaseRuleSet::get_beneficiary(header);
    }
    return ecrecover(header);
}

}  // namespace silkworm::protocol
