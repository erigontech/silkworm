/*
   Copyright 2021 The Silkworm Authors

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

#include "engine.hpp"

namespace silkworm::consensus {

MergeEngine::MergeEngine(const ChainConfig& chain_config)
    : terminal_total_difficulty_{*chain_config.terminal_total_difficulty},
      ethash_engine_{chain_config},
      pos_engine_{chain_config} {}

ValidationResult MergeEngine::pre_validate_block(const Block&, BlockState&) {
    // TODO (Andrew) implement
    return ValidationResult::kUnknownConsensusEngine;
}

ValidationResult MergeEngine::validate_block_header(const BlockHeader&, BlockState&, bool) {
    // TODO (Andrew) implement
    return ValidationResult::kUnknownConsensusEngine;
}

ValidationResult MergeEngine::validate_seal(const BlockHeader& header) {
    if (header.difficulty != 0) {
        return ethash_engine_.validate_seal(header);
    } else {
        return pos_engine_.validate_seal(header);
    }
}

void MergeEngine::finalize(IntraBlockState& state, const Block& block, evmc_revision revision) {
    if (block.header.difficulty != 0) {
        ethash_engine_.finalize(state, block, revision);
    } else {
        pos_engine_.finalize(state, block, revision);
    }
}

evmc::address MergeEngine::get_beneficiary(const BlockHeader& header) { return header.beneficiary; }

}  // namespace silkworm::consensus
