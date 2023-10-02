/*
   Copyright 2023 The Silkworm Authors

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

#include "bor_rule_set.hpp"

#include <silkworm/core/protocol/param.hpp>

namespace silkworm::protocol {

ValidationResult BorRuleSet::validate_block_header(const BlockHeader& header, const BlockState& state,
                                                   bool with_future_timestamp_check) {
    if (!is_zero(header.prev_randao)) {
        return ValidationResult::kInvalidMixDigest;
    }
    return BaseRuleSet::validate_block_header(header, state, with_future_timestamp_check);
}

// validate_extra_data validates that the extra-data contains both the vanity and signature.
// header.Extra = header.Vanity + header.ProducerBytes (optional) + header.Seal
ValidationResult BorRuleSet::validate_extra_data(const BlockHeader& header) {
    static constexpr size_t kExtraVanitySize{32};
    if (header.extra_data.length() < kExtraVanitySize) {
        return ValidationResult::kMissingVanity;
    }
    if (header.extra_data.length() < kExtraVanitySize + kExtraSealSize) {
        return ValidationResult::kMissingSignature;
    }
    return ValidationResult::kOk;
}

evmc::address BorRuleSet::get_beneficiary(const BlockHeader& header) {
    // TODO(yperbasis) implement properly
    return BaseRuleSet::get_beneficiary(header);
}

}  // namespace silkworm::protocol
