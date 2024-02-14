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

#include <silkworm/core/common/overloaded.hpp>

#include "bor_rule_set.hpp"
#include "clique_rule_set.hpp"
#include "ethash_rule_set.hpp"
#include "merge_rule_set.hpp"

namespace silkworm::protocol {

static RuleSetPtr pre_merge_rule_set(const ChainConfig& chain_config) {
    return std::visit<RuleSetPtr>(
        Overloaded{
            [&](const NoPreMergeConfig&) { return nullptr; },
            [&](const EthashConfig&) { return std::make_unique<EthashRuleSet>(chain_config); },
            [&](const CliqueConfig&) { return std::make_unique<CliqueRuleSet>(chain_config); },
            [&](const bor::Config&) { return std::make_unique<BorRuleSet>(chain_config); },
        },
        chain_config.rule_set_config);
}

RuleSetPtr rule_set_factory(const ChainConfig& chain_config) {
    RuleSetPtr rule_set{pre_merge_rule_set(chain_config)};
    if (chain_config.terminal_total_difficulty) {
        rule_set = std::make_unique<MergeRuleSet>(std::move(rule_set), chain_config);
    }
    return rule_set;
}

}  // namespace silkworm::protocol
