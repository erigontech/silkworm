/*
   Copyright 2022 The Silkworm Authors

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

#include "chain_fork_view.hpp"

#include <silkworm/core/types/block.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/db/stages.hpp>

namespace silkworm::chainsync {

ChainForkView::ChainForkView(ChainHead head, execution::Client& ec) : initial_head_{head}, exec_client_{ec}, td_cache_{kCacheSize} {
    current_head_ = initial_head_;
}

void ChainForkView::reset_head(BlockId new_head) {
    auto td = get_total_difficulty(new_head.number, new_head.hash);
    if (!td) throw std::logic_error("ChainForkView resetting head to unknown header");
    current_head_ = {new_head.number, new_head.hash, *td};
}

bool ChainForkView::head_changed() const { return current_head_.total_difficulty != initial_head_.total_difficulty; }

BlockNum ChainForkView::head_height() const { return current_head_.height; }

Hash ChainForkView::head_hash() const { return current_head_.hash; }

BigInt ChainForkView::head_total_difficulty() const { return current_head_.total_difficulty; }

ChainHead ChainForkView::head() const { return current_head_; }

TotalDifficulty ChainForkView::add(const BlockHeader& header) {  // try to modularize this method
    auto height = header.number;
    Hash hash = header.hash();

    // Calculate total difficulty
    auto parent_td = get_total_difficulty(height - 1, header.parent_hash);  // search in cache, then ask execution engine
    if (!parent_td) {                                                       /* clang-format off */
        std::string error_message = "Consensus: parent's total difficulty not found on Execution,"
            " hash= " + to_hex(header.parent_hash) +
            " height= " + std::to_string(height - 1) +
            " for header= " + hash.to_hex();
        log::Error("Consensus") << error_message;
        throw std::logic_error(error_message);  // unexpected condition, bug?  /* clang-format on */
    }
    auto td = *parent_td + header.difficulty;  // calculated total difficulty of this header

    // Now we can decide whether this header will create a change in the canonical head
    if (td > current_head_.total_difficulty) {
        // Save progress
        current_head_.height = height;
        current_head_.hash = hash;
        current_head_.total_difficulty = td;  // this makes sure we end up choosing the chain with the max total difficulty
    }

    previous_hash_ = hash;
    td_cache_.put(hash, td);

    return td;
}

std::optional<TotalDifficulty> ChainForkView::get_total_difficulty([[maybe_unused]] BlockNum height, const Hash& hash) {
    return get_total_difficulty(hash);
}

std::optional<TotalDifficulty> ChainForkView::get_total_difficulty(const Hash& hash) {
    auto parent_td = td_cache_.get_as_copy(hash);  // find in cache
    if (!parent_td) //parent_td = db.get_header_td(height, hash);
        parent_td = 0; // todo: implement total difficulty save/load from db #########################################
    return parent_td;
}

}  // namespace silkworm::chainsync
