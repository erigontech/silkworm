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

#pragma once

#include <silkworm/core/protocol/base_rule_set.hpp>

namespace silkworm::protocol {

// Warning: most Bor logic is not implemented yet.
// TODO(yperbasis) implement
class BorRuleSet : public BaseRuleSet {
  public:
    explicit BorRuleSet(const ChainConfig& chain_config) : BaseRuleSet(chain_config, /*prohibit_ommers=*/true) {}

    ValidationResult validate_seal(const BlockHeader&) final {
        return ValidationResult::kOk;
    }

    void initialize(EVM&) final {}

    void finalize(IntraBlockState&, const Block&) final {}

    intx::uint256 difficulty(const BlockHeader&, const BlockHeader&) final { return 1; }
};

}  // namespace silkworm::protocol
