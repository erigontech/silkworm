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

#include <silkworm/trie/vector_root.hpp>

#include "difficulty.hpp"

namespace silkworm {

static std::optional<BlockHeader> get_parent(const StateBuffer& state, const BlockHeader& header) {
    return state.read_header(header.number - 1, header.parent_hash);
}

ValidationError validate_block_header(const BlockHeader& header, const StateBuffer& state, const ChainConfig& config) {
    // TODO[Issue 144] Ethash PoW verification

    if (header.gas_used > header.gas_limit) {
        return ValidationError::kGasAboveLimit;
    }

    if (header.gas_limit < 5000) {
        return ValidationError::kInvalidGasLimit;
    }

    std::optional<BlockHeader> parent{get_parent(state, header)};
    if (!parent) {
        return ValidationError::kUnknownParent;
    }

    if (header.timestamp <= parent->timestamp) {
        return ValidationError::kInvalidTimestamp;
    }

    uint64_t gas_delta{header.gas_limit > parent->gas_limit ? header.gas_limit - parent->gas_limit
                                                            : parent->gas_limit - header.gas_limit};
    if (gas_delta >= parent->gas_limit / 1024) {
        return ValidationError::kInvalidGasLimit;
    }

    bool parent_has_uncles{parent->ommers_hash != kEmptyListHash};
    intx::uint256 difficulty{canonical_difficulty(header.number, header.timestamp, parent->difficulty,
                                                  parent->timestamp, parent_has_uncles, config)};
    if (difficulty != header.difficulty) {
        return ValidationError::kWrongDifficulty;
    }

    return ValidationError::kOk;
}

// See [YP] Section 11.1 "Ommer Validation"
static bool is_kin(const BlockHeader& u, const BlockHeader& h, unsigned n, const StateBuffer& state) {
    if (n == 0) {
        return false;
    }

    std::optional<BlockHeader> ph{get_parent(state, h)};
    std::optional<BlockHeader> pu{get_parent(state, u)};

    if (!ph) {
        return false;
    }

    bool siblings{ph == pu && h != u};
    if (siblings) {
        return true;
    }

    return is_kin(u, *ph, n - 1, state);
}

ValidationError pre_validate_block(const Block& block, const StateBuffer& state, const ChainConfig& config) {
    const BlockHeader& header{block.header};

    if (ValidationError err{validate_block_header(header, state, config)}; err != ValidationError::kOk) {
        return err;
    }

    Bytes ommers_rlp;
    rlp::encode(ommers_rlp, block.ommers);
    ethash::hash256 ommers_hash{keccak256(ommers_rlp)};
    if (full_view(ommers_hash.bytes) != full_view(header.ommers_hash)) {
        return ValidationError::kWrongOmmersHash;
    }

    evmc::bytes32 txn_root{trie::root_hash(block.transactions)};
    if (txn_root != header.transactions_root) {
        return ValidationError::kWrongTransactionsRoot;
    }

    if (block.ommers.size() > 2) {
        return ValidationError::kTooManyOmmers;
    }

    if (block.ommers.size() == 2 && block.ommers[0] == block.ommers[1]) {
        return ValidationError::kDuplicateOmmer;
    }

    std::optional<BlockHeader> parent{get_parent(state, header)};

    for (const BlockHeader& ommer : block.ommers) {
        if (ValidationError err{validate_block_header(ommer, state, config)}; err != ValidationError::kOk) {
            return ValidationError::kInvalidOmmerHeader;
        }
        if (!is_kin(ommer, *parent, 6, state)) {
            return ValidationError::kNotAnOmmer;
        }
    }

    return ValidationError::kOk;
}

}  // namespace silkworm
