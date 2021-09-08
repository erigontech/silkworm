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

#include <silkworm/trie/vector_root.hpp>
#include <silkworm/chain/intrinsic_gas.hpp>
#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/chain/difficulty.hpp>
#include <silkworm/crypto/ecdsa.hpp>

#include "clique.hpp"

namespace silkworm::consensus {

ValidationResult Clique::pre_validate_block(const Block& block, const State& state, const ChainConfig& config) {
    const BlockHeader& header{block.header};

    if (ValidationResult err{validate_block_header(header, state, config)}; err != ValidationResult::kOk) {
        return err;
    }

    // In Clique POA there must be no ommers, since uncles are not allowed
    if (!block.ommers.empty()) {
        return ValidationResult::kWrongOmmersHash;
    }

    return ValidationResult::kOk;
}

ValidationResult Clique::validate_block_header(const BlockHeader& , const State& , const ChainConfig& ) {
    static_cast<void>(clique_config_);
    static_cast<void>(snapshot_config_);

    return ValidationResult::kOk;
}

// There are no rewards in Clique POA consensus
void Clique::apply_rewards(IntraBlockState&, const Block&, const evmc_revision&) {}

}