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

#pragma once

#include <silkworm/core/protocol/base_rule_set.hpp>

namespace silkworm::protocol {

// Warning: most Clique (EIP-225) logic is not implemented yet.
// This rule set is just a dummy!
class CliqueRuleSet : public BaseRuleSet {
  public:
    explicit CliqueRuleSet(const ChainConfig& chain_config) : BaseRuleSet(chain_config, false) {}

    //! \brief Validates the seal of the header
    ValidationResult validate_seal(const BlockHeader& header) final;

    void initialize(EVM&) final {}

    void finalize(IntraBlockState&, const Block&) final {}

    evmc::address get_beneficiary(const BlockHeader& header) final;

  protected:
    intx::uint256 difficulty(const BlockHeader&, const BlockHeader&) const final { return 1; }
};

}  // namespace silkworm::protocol
