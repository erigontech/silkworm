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

#include "validity.hpp"

#include "difficulty.hpp"

namespace silkworm {

ValidationError validate_block_header(const BlockHeader& header, const StateBuffer& state, const ChainConfig& config) {
    // TODO[Issue 144] Ethash PoW verification

    std::optional<BlockHeader> parent{state.read_header(header.number - 1, header.parent_hash)};
    if (!parent) {
        return ValidationError::kUnknownParent;
    }

    bool parent_has_uncles{parent->ommers_hash != kEmptyListHash};
    intx::uint256 difficulty{canonical_difficulty(header.number, header.timestamp, parent->difficulty,
                                                  parent->timestamp, parent_has_uncles, config)};
    if (difficulty != header.difficulty) {
        return ValidationError::kWrongDifficulty;
    }

    if (header.gas_used > header.gas_limit) {
        return ValidationError::kGasAboveLimit;
    }

    uint64_t diff{header.gas_limit > parent->gas_limit ? header.gas_limit - parent->gas_limit
                                                       : parent->gas_limit - header.gas_limit};
    if (diff >= parent->gas_limit / 1024) {
        return ValidationError::kInvalidGasLimit;
    }

    if (header.gas_limit < 5000) {
        return ValidationError::kInvalidGasLimit;
    }

    if (header.timestamp <= parent->timestamp) {
        return ValidationError::kInvalidTimestamp;
    }

    return ValidationError::kOk;
}

ValidationError pre_validate_block(const Block& block, const StateBuffer& state, const ChainConfig& config) {
    if (ValidationError err{validate_block_header(block.header, state, config)}; err != ValidationError::kOk) {
        return err;
    }

    Bytes ommers_rlp;
    rlp::encode(ommers_rlp, block.ommers);
    ethash::hash256 ommers_hash{keccak256(ommers_rlp)};
    if (full_view(ommers_hash.bytes) != full_view(block.header.ommers_hash)) {
        return ValidationError::kWrongOmmersHash;
    }

    return ValidationError::kOk;
}

}  // namespace silkworm
