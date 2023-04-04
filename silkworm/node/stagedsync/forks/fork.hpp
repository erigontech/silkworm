/*
   Copyright 2023 The Silkworm Authors

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

#pragma once

#include <atomic>
#include <concepts>
#include <set>
#include <variant>
#include <vector>

#include <silkworm/core/common/as_range.hpp>
#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/infra/common/asio_timer.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/node/stagedsync/execution_pipeline.hpp>
#include <silkworm/node/stagedsync/stages/stage.hpp>

#include "canonical_chain.hpp"

namespace silkworm::stagedsync {

class Fork {
  public:
    explicit Fork(BlockId forking_point, NodeSettings&, db::RWAccess);
    Fork(Fork&&);

    // clang-format off
    struct ValidChain { BlockId current_head; };
    struct InvalidChain { BlockId unwind_point; std::optional<Hash> bad_block; std::set<Hash> bad_headers; };
    struct ValidationError { BlockId latest_valid_head; };
    // clang-format on
    using VerificationResult = std::variant<ValidChain, InvalidChain, ValidationError>;

    // extension
    void extend_with(const Block&);  // put block over the head of the fork
    bool extends_head(const BlockHeader&) const;

    // branching
    Fork branch_at(BlockId forking_point, db::RWAccess);
    std::optional<BlockId> find_attachment_point(const BlockHeader& header, const Hash& header_hash) const;
    BlockNum distance_from_root(const BlockId&) const;

    // verification
    auto verify_chain(Hash head_block_hash) -> VerificationResult;  // verify chain up to head_block_hash
    bool notify_fork_choice_update(Hash head_block_hash,            // accept the current chain up to head_block_hash
                                   std::optional<Hash> finalized_block_hash = std::nullopt);

    // state
    auto current_head() const -> BlockId;
    auto last_verified_head() const -> BlockId;
    auto last_head_status() const -> VerificationResult;

    // header/body retrieval
    auto get_block_progress() -> BlockNum;
    auto get_header(Hash) -> std::optional<BlockHeader>;
    auto get_header(BlockNum, Hash) -> std::optional<BlockHeader>;
    auto get_canonical_hash(BlockNum) -> std::optional<Hash>;
    auto get_header_td(BlockNum, Hash) -> std::optional<TotalDifficulty>;
    auto get_body(Hash) -> std::optional<BlockBody>;
    auto get_last_headers(BlockNum limit) -> std::vector<BlockHeader>;
    auto extends_last_fork_choice(BlockNum, Hash) -> bool;
    auto extends(BlockId block, BlockId supposed_parent) -> bool;
    auto is_ancestor(BlockId supposed_parent, BlockId block) -> bool;
    auto is_ancestor(Hash supposed_parent, BlockId block) -> bool;

  protected:
    Hash insert_header(const BlockHeader&);
    void insert_body(const Block&);

    std::set<Hash> collect_bad_headers(db::RWTxn& tx, InvalidChain& invalid_chain);

    NodeSettings& node_settings_;
    db::RWAccess db_access_;
    db::RWTxn tx_;
    bool is_first_sync_{true};

    // lru_cache<Hash, BlockHeader> header_cache_;  // use cache if it improves performances

    ExecutionPipeline pipeline_;
    CanonicalChain canonical_chain_;
    VerificationResult canonical_head_status_;

    BlockId current_head_;
    BlockId last_fork_choice_;
};

// find the fork with the head to extend
auto fork_to_extend(const std::vector<Fork>& forks, const BlockHeader& header)
    -> std::vector<Fork>::const_iterator {
    auto f = forks.begin();
    while (f != forks.end() && !f->extends_head(header))  // return the first with head == header.parent_hash
        f++;
    return f;
}

// find the best fork to branch from
auto best_fork_to_branch(const std::vector<Fork>& forks, const BlockHeader& header, const Hash& header_hash)
    -> std::vector<Fork>::const_iterator {
    auto fork = forks.end();
    BlockNum height = 0;
    for (auto f = forks.begin(); f != forks.end(); ++f) {
        auto attachment_point = f->find_attachment_point(header, header_hash);
        if (!attachment_point) continue;
        auto distance = f->distance_from_root(*attachment_point);
        if (fork == forks.end() || distance < height) {
            height = distance;
            fork = f;
        }
    }

    return fork;
}

}  // namespace silkworm::stagedsync
