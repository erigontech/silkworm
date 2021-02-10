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

ValidationResult validate_block_header(const BlockHeader& header, const StateBuffer& state, const ChainConfig& config) {
    // TODO[Issue 144] Ethash PoW verification

    if (header.gas_used > header.gas_limit) {
        return ValidationResult::kGasAboveLimit;
    }

    if (header.gas_limit < 5000) {
        return ValidationResult::kInvalidGasLimit;
    }

    // https://github.com/ethereum/go-ethereum/blob/v1.9.25/consensus/ethash/consensus.go#L267
    // https://eips.ethereum.org/EIPS/eip-1985
    if (header.gas_limit > 0x7fffffffffffffff) {
        return ValidationResult::kInvalidGasLimit;
    }

    std::optional<BlockHeader> parent{get_parent(state, header)};
    if (!parent) {
        return ValidationResult::kUnknownParent;
    }

    if (header.timestamp <= parent->timestamp) {
        return ValidationResult::kInvalidTimestamp;
    }

    uint64_t gas_delta{header.gas_limit > parent->gas_limit ? header.gas_limit - parent->gas_limit
                                                            : parent->gas_limit - header.gas_limit};
    if (gas_delta >= parent->gas_limit / 1024) {
        return ValidationResult::kInvalidGasLimit;
    }

    bool parent_has_uncles{parent->ommers_hash != kEmptyListHash};
    intx::uint256 difficulty{canonical_difficulty(header.number, header.timestamp, parent->difficulty,
                                                  parent->timestamp, parent_has_uncles, config)};
    if (difficulty != header.difficulty) {
        return ValidationResult::kWrongDifficulty;
    }

    // https://eips.ethereum.org/EIPS/eip-779
    if (config.dao_block && *config.dao_block <= header.number && header.number <= *config.dao_block + 9) {
        static const Bytes kDaoExtraData{*from_hex("0x64616f2d686172642d666f726b")};
        if (header.extra_data() != kDaoExtraData) {
            return ValidationResult::kWrongDaoExtraData;
        }
    }

    return ValidationResult::kOk;
}

// See [YP] Section 11.1 "Ommer Validation"
static bool is_kin(const BlockHeader& branch_header, const BlockHeader& mainline_header,
                   const evmc::bytes32& mainline_hash, unsigned n, const StateBuffer& state,
                   std::vector<BlockHeader>& old_ommers) {
    if (n == 0 || branch_header == mainline_header) {
        return false;
    }

    std::optional<BlockBody> mainline_body{state.read_body(mainline_header.number, mainline_hash)};
    if (!mainline_body) {
        return false;
    }
    old_ommers.insert(old_ommers.end(), mainline_body->ommers.begin(), mainline_body->ommers.end());

    std::optional<BlockHeader> mainline_parent{get_parent(state, mainline_header)};
    std::optional<BlockHeader> branch_parent{get_parent(state, branch_header)};

    if (!mainline_parent) {
        return false;
    }

    bool siblings{branch_parent == mainline_parent};
    if (siblings) {
        return true;
    }

    return is_kin(branch_header, *mainline_parent, mainline_header.parent_hash, n - 1, state, old_ommers);
}

ValidationResult pre_validate_block(const Block& block, const StateBuffer& state, const ChainConfig& config) {
    const BlockHeader& header{block.header};

    if (ValidationResult err{validate_block_header(header, state, config)}; err != ValidationResult::kOk) {
        return err;
    }

    Bytes ommers_rlp;
    rlp::encode(ommers_rlp, block.ommers);
    ethash::hash256 ommers_hash{keccak256(ommers_rlp)};
    if (full_view(ommers_hash.bytes) != full_view(header.ommers_hash)) {
        return ValidationResult::kWrongOmmersHash;
    }

    evmc::bytes32 txn_root{trie::root_hash(block.transactions)};
    if (txn_root != header.transactions_root) {
        return ValidationResult::kWrongTransactionsRoot;
    }

    if (block.ommers.size() > 2) {
        return ValidationResult::kTooManyOmmers;
    }

    if (block.ommers.size() == 2 && block.ommers[0] == block.ommers[1]) {
        return ValidationResult::kDuplicateOmmer;
    }

    std::optional<BlockHeader> parent{get_parent(state, header)};

    for (const BlockHeader& ommer : block.ommers) {
        if (ValidationResult err{validate_block_header(ommer, state, config)}; err != ValidationResult::kOk) {
            return ValidationResult::kInvalidOmmerHeader;
        }
        std::vector<BlockHeader> old_ommers;
        if (!is_kin(ommer, *parent, header.parent_hash, 6, state, old_ommers)) {
            return ValidationResult::kNotAnOmmer;
        }
        for (const BlockHeader& oo : old_ommers) {
            if (oo == ommer) {
                return ValidationResult::kDuplicateOmmer;
            }
        }
    }

    return ValidationResult::kOk;
}

}  // namespace silkworm
