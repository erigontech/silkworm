// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "chain_fork_view.hpp"

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::chainsync {

ChainForkView::ChainForkView(ChainHead head) : td_cache_{kCacheSize} {
    reset_head(head);
}

void ChainForkView::reset_head(ChainHead new_head) {
    initial_head_ = new_head;
    current_head_ = initial_head_;
    td_cache_.put(current_head_.hash, current_head_.total_difficulty);
}

ChainHead ChainForkView::head_at_genesis(const ChainConfig& chain_config) {
    bool allow_exceptions = false;
    auto source_data = read_genesis_data(chain_config.chain_id);
    auto genesis_json = nlohmann::json::parse(source_data, nullptr, allow_exceptions);
    BlockHeader header = read_genesis_header(genesis_json, kEmptyRoot);
    return {header.number, header.hash(), header.difficulty};
}

bool ChainForkView::head_changed() const { return current_head_.total_difficulty != initial_head_.total_difficulty; }

BlockNum ChainForkView::head_block_num() const { return current_head_.block_num; }

Hash ChainForkView::head_hash() const { return current_head_.hash; }

BigInt ChainForkView::head_total_difficulty() const { return current_head_.total_difficulty; }

ChainHead ChainForkView::head() const { return current_head_; }

TotalDifficulty ChainForkView::add(const BlockHeader& header) {
    // Calculate parent total difficulty
    auto parent_td = get_total_difficulty(header.number - 1, header.parent_hash);  // search in cache
    if (!parent_td) {                                                              /* clang-format off */
        std::string error_message = "Consensus: parent's total difficulty not found,"
            " hash= " + to_hex(header.parent_hash) +
            " block_num= " + std::to_string(header.number - 1) +
            " for header= " + to_hex(header.hash());
        SILK_ERROR_M("chainsync::ChainForkView") << error_message;
        throw std::logic_error(error_message);  // unexpected condition, bug?  /* clang-format on */
    }
    return add(header, *parent_td);
}

TotalDifficulty ChainForkView::add(const BlockHeader& header, TotalDifficulty parent_td) {
    auto block_num = header.number;
    Hash hash = header.hash();

    auto td = parent_td + header.difficulty;  // calculated total difficulty of this header

    // Now we can decide whether this header will create a change in the canonical head
    if (td > current_head_.total_difficulty) {
        // Save progress
        current_head_.block_num = block_num;
        current_head_.hash = hash;
        current_head_.total_difficulty = td;  // this makes sure we end up choosing the chain with the max total difficulty
    }

    td_cache_.put(hash, td);

    return td;
}

std::optional<TotalDifficulty> ChainForkView::get_total_difficulty([[maybe_unused]] BlockNum block_num, const Hash& hash) {
    return get_total_difficulty(hash);
}

std::optional<TotalDifficulty> ChainForkView::get_total_difficulty(const Hash& hash) {
    auto parent_td = td_cache_.get_as_copy(hash);  // find in cache
    return parent_td;
}

}  // namespace silkworm::chainsync
