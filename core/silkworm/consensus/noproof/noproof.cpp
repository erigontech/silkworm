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

#include <silkworm/consensus/ethash/ethash.hpp>

#include "noproof.hpp"

namespace silkworm::consensus {

ValidationResult NoProof::pre_validate_block(const Block&, const State&, const ChainConfig&) {
    return ValidationResult::kOk;
}

ValidationResult NoProof::validate_block_header(const BlockHeader&, const State&, const ChainConfig&) {
    return ValidationResult::kOk;
}

void NoProof::apply_rewards(IntraBlockState& state, const Block& block, const evmc_revision& revision) {
    Ethash().apply_rewards(state, block, revision);
}

}