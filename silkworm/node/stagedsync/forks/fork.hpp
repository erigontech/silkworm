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
#include <optional>
#include <set>
#include <variant>
#include <vector>

#include <silkworm/core/types/block.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/datastore/mdbx/memory_mutation.hpp>
#include <silkworm/execution/api/endpoint/validation.hpp>
#include <silkworm/node/stagedsync/execution_pipeline.hpp>

#include "../timer_factory.hpp"
#include "canonical_chain.hpp"

namespace silkworm::stagedsync {

class MainChain;

class Fork {
  public:
    explicit Fork(
        BlockId forking_point,
        db::ROTxnManaged main_tx,
        db::DataModelFactory data_model_factory,
        std::optional<TimerFactory> log_timer_factory,
        const StageContainerFactory& stages_factory,
        const std::filesystem::path& forks_dir_path);
    Fork(const Fork&) = delete;

    void close();
    void flush(db::RWTxn& main_chain_tx_);

    // extension & contraction
    void extend_with(const std::list<std::shared_ptr<Block>>&);
    void extend_with(const Block&);             // put block over the head of the fork (need verify_chain() to add state)
    void reduce_down_to(BlockId unwind_point);  // remove blocks & state down to the specified head

    // verification
    using VerificationResult = execution::api::VerificationResult;
    // verify chain up to current head
    VerificationResult verify_chain();
    // accept the current chain up to head_block_hash
    bool fork_choice(Hash head_block_hash, std::optional<Hash> finalized_block_hash = {}, std::optional<Hash> safe_block_hash = {});

    // state
    BlockId current_head() const;
    std::optional<VerificationResult> head_status() const;
    BlockId finalized_head() const;
    BlockId safe_head() const;

    // checks
    bool extends_head(const BlockHeader&) const;
    std::optional<BlockNum> find_block(Hash header_hash) const;
    std::optional<BlockId> find_attachment_point(const BlockHeader& header) const;
    BlockNum distance_from_root(const BlockId&) const;

    // header/body retrieval
    std::optional<BlockHeader> get_header(Hash) const;

  protected:
    db::DataModel data_model() const { return data_model_factory_(memory_tx_); }
    Hash insert_header(const BlockHeader&);
    void insert_body(const Block&, const Hash& block_hash);

    std::set<Hash> collect_bad_headers(execution::api::InvalidChain& invalid_chain);

    db::ROTxnManaged main_tx_;
    db::MemoryOverlay memory_db_;
    mutable db::MemoryMutation memory_tx_;
    db::DataModelFactory data_model_factory_;

    ExecutionPipeline pipeline_;
    CanonicalChain canonical_chain_;

    BlockId current_head_;
    std::optional<VerificationResult> head_status_;
    BlockId finalized_head_;
    BlockId safe_head_;
};

// find the fork with the specified head
std::vector<Fork>::iterator find_fork_by_head(const std::vector<Fork>& forks, const Hash& requested_head_hash);

// find the fork with the head to extend
std::vector<Fork>::iterator find_fork_to_extend(const std::vector<Fork>& forks, const BlockHeader& header);

}  // namespace silkworm::stagedsync
