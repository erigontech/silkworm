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

#ifndef SILKWORM_CONSENSUS_CLIQUE
#define SILKWORM_CONSENSUS_CLIQUE

#include <silkworm/consensus/consensus_engine.hpp>

namespace silkworm::consensus {

// Proof of Authority (Clique) implementation
class Clique: public ConsensusEngine {

    public:

     Clique(CliqueConfig clique_config): 
        clique_config_{clique_config} {}

     ValidationResult pre_validate_block(const Block& block, State& state, const ChainConfig& config) override;

     ValidationResult validate_block_header(const BlockHeader& header, State& state, const ChainConfig& config) override;

     void apply_rewards(IntraBlockState& state, const Block& block, const evmc_revision& revision) override;

     evmc::address get_beneficiary(const BlockHeader& header) override;

     std::optional<evmc::address> get_signer_from_clique_header(BlockHeader header);
    private:

     CliqueConfig   clique_config_;
     CliqueSnapshot last_snapshot_{}; // We cache it to avoid writes and reads
     std::map<evmc::bytes32, evmc::address> sig_cache_;  // Cache where signatures are stored
};

}
#endif // SILKWORM_CONSENSUS_CLIQUE