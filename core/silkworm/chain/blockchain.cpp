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

#include "blockchain.hpp"

#include <silkworm/execution/execution.hpp>

namespace silkworm {

Blockchain::Blockchain(StateBuffer& state, const ChainConfig& config, const Block& genesis_block)
    : state_{state}, config_{config} {
    evmc::bytes32 hash{genesis_block.header.hash()};
    state_.insert_block(genesis_block, hash);
    state_.canonize_block(genesis_block.header.number, hash);
}

ValidationError Blockchain::insert_block(Block& block, bool check_state_root) {
    if (ValidationError err{pre_validate_block(block, state_, config_)}; err != ValidationError::kOk) {
        return err;
    }

    block.recover_senders(config_);

    evmc::bytes32 hash{block.header.hash()};
    state_.insert_block(block, hash);

    uint64_t current_canonical_block{state_.current_canonical_block()};
    intx::uint256 current_total_difficulty{
        *state_.total_difficulty(current_canonical_block, *state_.canonical_hash(current_canonical_block))};

    if (state_.total_difficulty(block.header.number, hash) <= current_total_difficulty) {
        return ValidationError::kOk;
    }

    uint64_t ancestor{canonical_ancestor(block.header, hash)};
    decanonize_chain(ancestor);
    return canonize_chain(block, hash, ancestor, check_state_root);
}

ValidationError Blockchain::execute_and_canonize_block(const Block& block, const evmc::bytes32& hash,
                                                       bool check_state_root) {
    std::pair<std::vector<Receipt>, ValidationError> res{execute_block(block, state_, config_)};
    if (res.second != ValidationError::kOk) {
        return res.second;
    }

    if (check_state_root) {
        evmc::bytes32 state_root{state_.state_root_hash()};
        if (state_root != block.header.state_root) {
            state_.unwind_state_changes(block.header.number);
            return ValidationError::kWrongStateRoot;
        }
    }

    state_.canonize_block(block.header.number, hash);

    return ValidationError::kOk;
}

ValidationError Blockchain::canonize_chain(const Block& block, evmc::bytes32 hash, uint64_t canonical_ancestor,
                                           bool check_state_root) {
    std::vector<BlockWithHash> chain(block.header.number - canonical_ancestor);

    for (uint64_t block_number{block.header.number}; block_number > canonical_ancestor; --block_number) {
        BlockWithHash& x{chain[block_number - canonical_ancestor - 1]};

        std::optional<BlockBody> body{state_.read_body(block_number, hash)};
        std::optional<BlockHeader> header{state_.read_header(block_number, hash)};
        x.block.header = *header;
        x.block.transactions = body->transactions;
        x.block.ommers = body->ommers;
        x.hash = hash;

        hash = header->parent_hash;
    }

    for (const BlockWithHash& x : chain) {
        if (ValidationError err{execute_and_canonize_block(x.block, x.hash, check_state_root)};
            err != ValidationError::kOk) {
            // TODO(Andrew) mark this & subsequent blocks as invalid and remove them from the state
            return err;
        }
    }

    return ValidationError::kOk;
}

void Blockchain::decanonize_chain(uint64_t back_to) {
    while (true) {
        uint64_t block_number{state_.current_canonical_block()};
        if (block_number <= back_to) {
            return;
        }
        state_.unwind_state_changes(block_number);
        state_.decanonize_block(block_number);
    }
}

uint64_t Blockchain::canonical_ancestor(const BlockHeader& header, const evmc::bytes32& hash) const {
    if (state_.canonical_hash(header.number) == hash) {
        return header.number;
    }
    std::optional<BlockHeader> parent{state_.read_header(header.number - 1, header.parent_hash)};
    return canonical_ancestor(*parent, header.parent_hash);
}

}  // namespace silkworm
