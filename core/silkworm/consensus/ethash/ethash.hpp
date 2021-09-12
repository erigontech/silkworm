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

#ifndef SILKWORM_CONSENSUS_ETHASH
#define SILKWORM_CONSENSUS_ETHASH

#include <silkworm/consensus/consensus_engine.hpp>

namespace silkworm::consensus {
// Proof of Work implementation
class Ethash: public ConsensusEngine {

    public:

     ValidationResult pre_validate_block(const Block& block, State& state, const ChainConfig& config) override;

     ValidationResult validate_block_header(const BlockHeader& header, State& state, const ChainConfig& config) override;

     void apply_rewards(IntraBlockState& state, const Block& block, const evmc_revision& revision) override;

    void assign_transaction_fees(const BlockHeader& header, intx::uint256 accumulated_fees, IntraBlockState& state) override;
};

}
#endif // SILKWORM_CONSENSUS_ETHASH