// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "blockchain.hpp"

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/execution/processor.hpp>

#include "silkworm/core/state/in_memory_state.hpp"

namespace silkworm::protocol {

Blockchain::Blockchain(State& state, const ChainConfig& config, const Block& genesis_block)
    : state_{state}, config_{config}, rule_set_{rule_set_factory(config)} {
    prime_state_with_genesis(genesis_block);
}

ValidationResult Blockchain::insert_block(Block& block, bool check_state_root) {
    ValidationResult err{rule_set_->validate_block_header(block.header, state_, /*with_future_timestamp_check=*/false)};
    if (err != ValidationResult::kOk) {
        return err;
    }
    err = rule_set_->pre_validate_block_body(block, state_);
    if (err != ValidationResult::kOk) {
        return err;
    }

    evmc::bytes32 hash{block.header.hash()};
    if (auto it{bad_blocks_.find(hash)}; it != bad_blocks_.end()) {
        return it->second;
    }

    uint64_t ancestor{canonical_ancestor(block.header, hash)};
    uint64_t current_canonical_block{state_.current_canonical_block()};
    unwind_last_changes(ancestor, current_canonical_block);

    uint64_t block_num = block.header.number;

    std::vector<BlockWithHash> chain{intermediate_chain(block_num - 1, block.header.parent_hash, ancestor)};
    chain.push_back({block, hash});

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

    // Non-strict comparison because of the Merge
    if (state_.total_difficulty(block_num, hash) >= current_total_difficulty) {
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
    ExecutionProcessor processor{block, *rule_set_, state_, config_, true};
    processor.evm().exo_evm = exo_evm;

    if (const ValidationResult res = processor.execute_block(receipts_); res != ValidationResult::kOk) {
        return res;
    }

    processor.flush_state();

    if (check_state_root) {
        evmc::bytes32 state_root{state_.state_root_hash()};
        if (state_root != block.header.state_root) {
            state_.unwind_state_changes(block.header.number);
            return ValidationResult::kWrongStateRoot;
        }
    }

    return ValidationResult::kOk;
}

void Blockchain::prime_state_with_genesis(const Block& genesis_block) {
    evmc::bytes32 hash{genesis_block.header.hash()};
    state_.insert_block(genesis_block, hash);
    state_.canonize_block(genesis_block.header.number, hash);
}

void Blockchain::re_execute_canonical_chain(uint64_t ancestor, uint64_t tip) {
    SILKWORM_ASSERT(ancestor <= tip);
    for (uint64_t block_num = ancestor + 1; block_num <= tip; ++block_num) {
        std::optional<evmc::bytes32> hash{state_.canonical_hash(block_num)};
        SILKWORM_ASSERT(hash != std::nullopt);
        BlockBody body;
        SILKWORM_ASSERT(state_.read_body(block_num, *hash, body));
        std::optional<BlockHeader> header{state_.read_header(block_num, *hash)};
        SILKWORM_ASSERT(header != std::nullopt);

        Block block;
        block.header = header.value();
        block.transactions = std::move(body.transactions);
        block.ommers = std::move(body.ommers);

        [[maybe_unused]] ValidationResult err{execute_block(block, /*check_state_root=*/false)};
        SILKWORM_ASSERT(err == ValidationResult::kOk);
    }
}

void Blockchain::unwind_last_changes(uint64_t ancestor, uint64_t tip) {
    SILKWORM_ASSERT(ancestor <= tip);
    for (uint64_t block_num{tip}; block_num > ancestor; --block_num) {
        state_.unwind_state_changes(block_num);
    }
}

std::vector<BlockWithHash> Blockchain::intermediate_chain(
    uint64_t block_num,
    evmc::bytes32 hash,
    uint64_t canonical_ancestor) const {
    SILKWORM_ASSERT(block_num >= canonical_ancestor);
    std::vector<BlockWithHash> chain(static_cast<size_t>(block_num - canonical_ancestor));

    for (; block_num > canonical_ancestor; --block_num) {
        BlockWithHash& x{chain[static_cast<size_t>(block_num - canonical_ancestor - 1)]};

        BlockBody body;
        SILKWORM_ASSERT(state_.read_body(block_num, hash, body));
        std::optional<BlockHeader> header{state_.read_header(block_num, hash)};
        SILKWORM_ASSERT(header != std::nullopt);

        x.block.header = *header;
        x.block.transactions = std::move(body.transactions);
        x.block.ommers = std::move(body.ommers);
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

    // Blockchain::insert_block fails for blocks whose parent is not in the state,
    // so all ancestors should be in the state.
    SILKWORM_ASSERT(parent != std::nullopt);

    return canonical_ancestor(*parent, header.parent_hash);
}

}  // namespace silkworm::protocol
