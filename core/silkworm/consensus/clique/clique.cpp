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

    // In Clique POA there must be no ommers
    Bytes ommers_rlp;
    rlp::encode(ommers_rlp, block.ommers);
    ethash::hash256 ommers_hash{keccak256(ommers_rlp)};
    if (full_view(ommers_hash.bytes) != full_view(kEmptyListHash)) {
        return ValidationResult::kWrongOmmersHash;
    }

    return ValidationResult::kOk;
}

ValidationResult Clique::validate_block_header(const BlockHeader& header, const State& state, const ChainConfig& config) {
    if (header.gas_used > header.gas_limit) {
        return ValidationResult::kGasAboveLimit;
    }

    if (header.gas_limit < 5000) {
        return ValidationResult::kInvalidGasLimit;
    }

    // https://github.com/ethereum/go-ethereum/blob/v1.9.25/consensus/ethash/consensus.go#L267
    // https://eips.ethereum.org/EIPS/eip-1985
    if (header.gas_limit > INT64_MAX) {
        return ValidationResult::kInvalidGasLimit;
    }

    if (header.extra_data.length() > 32) {
        return ValidationResult::kExtraDataTooLong;
    }

    const std::optional<BlockHeader> parent{get_parent(state, header)};
    if (!parent) {
        return ValidationResult::kUnknownParent;
    }

    if (header.timestamp <= parent->timestamp) {
        return ValidationResult::kInvalidTimestamp;
    }

    uint64_t parent_gas_limit{parent->gas_limit};
    if (header.number == config.revision_block(EVMC_LONDON)) {
        parent_gas_limit = parent->gas_limit * param::kElasticityMultiplier;  // EIP-1559
    }

    const uint64_t gas_delta{header.gas_limit > parent_gas_limit ? header.gas_limit - parent_gas_limit
                                                                 : parent_gas_limit - header.gas_limit};
    if (gas_delta >= parent_gas_limit / 1024) {
        return ValidationResult::kInvalidGasLimit;
    }

    const bool parent_has_uncles{parent->ommers_hash != kEmptyListHash};
    const intx::uint256 difficulty{canonical_difficulty(header.number, header.timestamp, parent->difficulty,
                                                        parent->timestamp, parent_has_uncles, config)};
    if (difficulty != header.difficulty) {
        return ValidationResult::kWrongDifficulty;
    }

    // https://eips.ethereum.org/EIPS/eip-779
    if (config.dao_block && *config.dao_block <= header.number && header.number <= *config.dao_block + 9) {
        static const Bytes kDaoExtraData{*from_hex("0x64616f2d686172642d666f726b")};
        if (header.extra_data != kDaoExtraData) {
            return ValidationResult::kWrongDaoExtraData;
        }
    }

    if (header.base_fee_per_gas != expected_base_fee_per_gas(header, *parent, config)) {
        return ValidationResult::kWrongBaseFee;
    }

    return ValidationResult::kOk;
}

// There are no rewards in Clique POA consensus
void Clique::apply_rewards(IntraBlockState&, const Block&, const evmc_revision&) {}

}