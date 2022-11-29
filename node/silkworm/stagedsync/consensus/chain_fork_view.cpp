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

#include <silkworm/common/log.hpp>
#include <silkworm/db/stages.hpp>

namespace silkworm::stagedsync::consensus {

ChainForkView::ChainForkView(ExecutionEngine& ee) : exec_engine_{ee} {
    std::tie(initial_head_.number, initial_head_.hash, initial_head_td_) = exec_engine_.get_headers_head();

    current_head_td_ = initial_head_td_;
    current_head_ = initial_head_;
}

bool ChainForkView::head_changed() const { return current_head_td_ != initial_head_td_; }

BlockNum ChainForkView::head_height() const { return current_head_.number; }

Hash ChainForkView::head_hash() const { return current_head_.hash; }

BigInt ChainForkView::head_total_difficulty() const { return current_head_td_; }

void ChainForkView::add(const BlockHeader& header) {  // try to modularize this method
    // Admittance conditions
    auto height = header.number;
    Hash hash = header.hash();
    if (hash == previous_hash_) {
        return;  // skip duplicates
    }

    // Calculate total difficulty
    auto parent_td = exec_engine_.get_header_td(height - 1, header.parent_hash);
    if (!parent_td) {
        std::string error_message = "Consensus: parent's total difficulty not found on Execution,"
            " hash= " + to_hex(header.parent_hash) +
            " height= " + std::to_string(height - 1) +
            " for header= " + hash.to_hex();
        log::Error("Consensus") << error_message;
        throw std::logic_error(error_message);  // unexpected condition, bug?
    }
    auto td = *parent_td + header.difficulty;  // calculated total difficulty of this header

    // Now we can decide whether this header will create a change in the canonical head
    if (td > current_head_td_) {
        // Save progress
        current_head_.number = height;
        current_head_.hash = hash;
        current_head_td_ = td;  // this makes sure we end up choosing the chain with the max total difficulty
    }

    previous_hash_ = hash;
}

}  // namespace silkworm::stagedsync::consensus
