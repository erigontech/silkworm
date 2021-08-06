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

#include <cassert>

#include <silkworm/execution/execution.hpp>

namespace silkworm {

Blockchain::Blockchain(StateBuffer& state, const ChainConfig& config, const Block& genesis_block)
    : state_{state}, config_{config} {
    evmc::bytes32 hash{genesis_block.header.hash()};
    state_.insert_block(genesis_block, hash);
    state_.canonize_block(genesis_block.header.number, hash);
}

ValidationResult Blockchain::insert_block(Block& block, bool check_state_root) {
    if (ValidationResult err{pre_validate_block(block, state_, config_)}; err != ValidationResult::kOk) {
        return err;
    }

    evmc::bytes32 hash{block.header.hash()};
    if (auto it{bad_blocks_.find(hash)}; it != bad_blocks_.end()) {
        return it->second;
    }

    block.recover_senders();

    uint64_t ancestor{canonical_ancestor(block.header, hash)};
    uint64_t current_canonical_block{state_.current_canonical_block()};
    unwind_last_changes(ancestor, current_canonical_block);

    uint64_t block_number{block.header.number};

    std::vector<BlockWithHash> chain{intermediate_chain(block_number - 1, block.header.parent_hash, ancestor)};
    chain.push_back({block, hash});

    ValidationResult err{ValidationResult::kOk};
    size_t num_of_executed_chain_blocks{0};
    for (const BlockWithHash& x : chain) {
        err = execute_block(x.block, check_state_root);
        if (err != ValidationResult::kOk) {
            break;
        }
        ++num_of_executed_chain_blocks;
    }

    if (err != ValidationResult::kOk) {
        bad_blocks_[hash] = err;
        unwind_last_changes(ancestor, ancestor + num_of_executed_chain_blocks);
        re_execute_canonical_chain(ancestor, current_canonical_block);
        return err;
    }

    state_.insert_block(block, hash);

    intx::uint256 current_total_difficulty{
        *state_.total_difficulty(current_canonical_block, *state_.canonical_hash(current_canonical_block))};

    if (state_.total_difficulty(block_number, hash) > current_total_difficulty) {
        // canonize the new chain
        for (uint64_t i{current_canonical_block}; i > ancestor; --i) {
            state_.decanonize_block(i);
        }
        for (const BlockWithHash& x : chain) {
            state_.canonize_block(x.block.header.number, x.hash);
        }
    } else {
        unwind_last_changes(ancestor, ancestor + num_of_executed_chain_blocks);
        re_execute_canonical_chain(ancestor, current_canonical_block);
    }

    return ValidationResult::kOk;
}

ValidationResult Blockchain::execute_block(const Block& block, bool check_state_root) {
    std::vector<Receipt> receipts;

    const ValidationResult res{
        silkworm::execute_block(block, state_, config_, receipts, /*analysis_cache=*/nullptr, state_pool, exo_evm)};
    if (res != ValidationResult::kOk) {
        return res;
    }

    if (check_state_root) {
        evmc::bytes32 state_root{state_.state_root_hash()};
        if (state_root != block.header.state_root) {
            state_.unwind_state_changes(block.header.number);
            return ValidationResult::kWrongStateRoot;
        }
    }

    return ValidationResult::kOk;
}

void Blockchain::re_execute_canonical_chain(uint64_t ancestor, uint64_t tip) {
    assert(ancestor <= tip);
    for (uint64_t block_number{ancestor + 1}; block_number <= tip; ++block_number) {
        std::optional<evmc::bytes32> hash{state_.canonical_hash(block_number)};
        std::optional<BlockBody> body{state_.read_body(block_number, *hash)};
        std::optional<BlockHeader> header{state_.read_header(block_number, *hash)};

        Block block;
        block.header = *header;
        block.transactions = body->transactions;
        block.ommers = body->ommers;

        [[maybe_unused]] ValidationResult err{execute_block(block, /*check_state_root=*/false)};
        assert(err == ValidationResult::kOk);
    }
}

void Blockchain::unwind_last_changes(uint64_t ancestor, uint64_t tip) {
    assert(ancestor <= tip);
    for (uint64_t block_number{tip}; block_number > ancestor; --block_number) {
        state_.unwind_state_changes(block_number);
    }
}

std::vector<BlockWithHash> Blockchain::intermediate_chain(uint64_t block_number, evmc::bytes32 hash,
                                                          uint64_t canonical_ancestor) const {
    std::vector<BlockWithHash> chain(block_number - canonical_ancestor);

    for (; block_number > canonical_ancestor; --block_number) {
        BlockWithHash& x{chain[block_number - canonical_ancestor - 1]};

        std::optional<BlockBody> body{state_.read_body(block_number, hash)};
        std::optional<BlockHeader> header{state_.read_header(block_number, hash)};
        x.block.header = *header;
        x.block.transactions = body->transactions;
        x.block.ommers = body->ommers;
        x.hash = hash;

        hash = header->parent_hash;
    }

    return chain;
}

uint64_t Blockchain::canonical_ancestor(const BlockHeader& header, const evmc::bytes32& hash) const {
    if (state_.canonical_hash(header.number) == hash) {
        return header.number;
    }
    std::optional<BlockHeader> parent{state_.read_header(header.number - 1, header.parent_hash)};
    return canonical_ancestor(*parent, header.parent_hash);
}

}  // namespace silkworm
