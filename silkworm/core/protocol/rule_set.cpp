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

#include "rule_set.hpp"

#include "bor_rule_set.hpp"
#include "clique_rule_set.hpp"
#include "ethash_rule_set.hpp"
#include "merge_rule_set.hpp"
#include "no_proof_rule_set.hpp"

namespace silkworm::protocol {

static RuleSetPtr pre_merge_rule_set(const ChainConfig& chain_config) {
    switch (chain_config.protocol_rule_set) {
        case RuleSetType::kEthash:
            return std::make_unique<EthashRuleSet>(chain_config);
        case RuleSetType::kNoProof:
            return std::make_unique<NoProofRuleSet>(chain_config);
        case RuleSetType::kClique:
            return std::make_unique<CliqueRuleSet>(chain_config);
        case RuleSetType::kBor:
            return std::make_unique<BorRuleSet>(chain_config);
        default:
            return nullptr;
    }
}

RuleSetPtr rule_set_factory(const ChainConfig& chain_config) {
    RuleSetPtr rule_set{pre_merge_rule_set(chain_config)};
    if (!rule_set) {
        return nullptr;
    }

    if (chain_config.terminal_total_difficulty) {
        rule_set = std::make_unique<MergeRuleSet>(std::move(rule_set), chain_config);
    }
    return rule_set;
}

}  // namespace silkworm::protocol
