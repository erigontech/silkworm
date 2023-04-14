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

#include <silkworm/core/types/block.hpp>
#include <silkworm/node/stagedsync/execution_pipeline.hpp>

#include "canonical_chain.hpp"
#include "silkworm/node/db/memory_mutation.hpp"
#include "verification_result.hpp"

namespace silkworm::stagedsync {

class MainChain;

class Fork {
  public:
    explicit Fork(BlockId forking_point, NodeSettings&, MainChain&);
    Fork(const Fork&) = delete;
    Fork(Fork&& orig) noexcept;

    void open();

    // extension & contraction
    void extend_with(const std::list<std::shared_ptr<Block>>&);
    void extend_with(const Block&);         // put block over the head of the fork (need verify_chain() to add state)
    void reduce_down_to(BlockId new_head);  // remove blocks & state down to the specified head

    // verification
    auto verify_chain() -> VerificationResult;            // verify chain up to current head
    bool notify_fork_choice_update(Hash head_block_hash,  // accept the current chain up to head_block_hash
                                   std::optional<Hash> finalized_block_hash = std::nullopt);

    // state
    auto current_head() const -> BlockId;
    auto last_verified_head() const -> BlockId;
    auto last_head_status() const -> VerificationResult;
    auto last_fork_choice() const -> BlockId;

    // checks
    bool extends_head(const BlockHeader&) const;
    auto find_block(Hash header_hash) const -> std::optional<BlockNum>;
    auto find_attachment_point(const BlockHeader& header) const -> std::optional<BlockId>;
    BlockNum distance_from_root(const BlockId&) const;

  protected:
    Hash insert_header(const BlockHeader&);
    void insert_body(const Block&, const Hash& block_hash);

    std::set<Hash> collect_bad_headers(db::RWTxn& tx, InvalidChain& invalid_chain);

    NodeSettings& node_settings_;

    MainChain& main_chain_;
    db::ROTxn db_tx_;
    db::MemoryOverlay overlay_;
    db::MemoryMutation tx_;

    ExecutionPipeline pipeline_;
    CanonicalChain canonical_chain_;

    BlockId current_head_;

    BlockId last_verified_head_;
    VerificationResult last_head_status_;
    BlockId last_fork_choice_;
};

// find the fork with the specified head
auto find_fork_by_head(const std::vector<Fork>& forks, const Hash& requested_head_hash)
    -> std::vector<Fork>::iterator;

// find the fork with the head to extend
auto find_fork_to_extend(const std::vector<Fork>& forks, const BlockHeader& header)
    -> std::vector<Fork>::iterator;

}  // namespace silkworm::stagedsync
