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

#include <ethash/ethash.hpp>

#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/common/endian.hpp>

namespace silkworm::consensus {

void ConsensusEngineEthash::finalize(IntraBlockState& state, const Block& block, const evmc_revision& revision) {
    intx::uint256 block_reward;
    if (revision >= EVMC_CONSTANTINOPLE) {
        block_reward = param::kBlockRewardConstantinople;
    } else if (revision >= EVMC_BYZANTIUM) {
        block_reward = param::kBlockRewardByzantium;
    } else {
        block_reward = param::kBlockRewardFrontier;
    }

    const uint64_t block_number{block.header.number};
    intx::uint256 miner_reward{block_reward};
    for (const BlockHeader& ommer : block.ommers) {
        intx::uint256 ommer_reward{((8 + ommer.number - block_number) * block_reward) >> 3};
        state.add_to_balance(ommer.beneficiary, ommer_reward);
        miner_reward += block_reward / 32;
    }

    state.add_to_balance(block.header.beneficiary, miner_reward);
}

ValidationResult ConsensusEngineEthash::validate_seal(const BlockHeader& header) {
    // Ethash ProofOfWork verification
    auto epoch_number{header.number / ethash::epoch_length};
    auto epoch_context{ethash::create_epoch_context(static_cast<int>(epoch_number))};

    auto boundary256{header.boundary()};
    auto seal_hash(header.hash(/*for_sealing =*/true));
    ethash::hash256 sealh256{*reinterpret_cast<ethash::hash256*>(seal_hash.bytes)};
    ethash::hash256 mixh256{};
    std::memcpy(mixh256.bytes, header.mix_hash.bytes, 32);

    uint64_t nonce{endian::load_big_u64(header.nonce.data())};
    return ethash::verify(*epoch_context, sealh256, mixh256, nonce, boundary256) ? ValidationResult::kOk
                                                                                 : ValidationResult::kInvalidSeal;
}
}  // namespace silkworm::consensus
