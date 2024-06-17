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

#include <boost/asio/io_context.hpp>

#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/db/mdbx/memory_mutation.hpp>
#include <silkworm/db/stage.hpp>
#include <silkworm/node/stagedsync/execution_pipeline.hpp>

#include "canonical_chain.hpp"
#include "verification_result.hpp"

namespace silkworm::stagedsync {

class Fork;
class ExtendingFork;

class MainChain {
  public:
    explicit MainChain(boost::asio::io_context&, NodeSettings&, db::RWAccess);

    void open();  // needed to circumvent mdbx threading model limitations
    void close();
    void abort();

    // extension
    void insert_block(const Block&);

    // branching
    std::unique_ptr<ExtendingFork> fork(BlockId forking_point);  // fort at the current head
    void reintegrate_fork(ExtendingFork&);                       // reintegrate fork into the main chain
    std::optional<BlockId> find_forking_point(const BlockHeader& header, const Hash& header_hash) const;
    std::optional<BlockId> find_forking_point(const Hash& header_hash) const;
    bool is_finalized_canonical(BlockId block) const;

    // verification
    // verify chain up to head_block_hash
    VerificationResult verify_chain(Hash head_block_hash);
    // accept the current chain up to head_block_hash
    bool notify_fork_choice_update(Hash head_block_hash, std::optional<Hash> finalized_block_hash = std::nullopt);

    // state
    BlockId last_chosen_head() const;  // set by notify_fork_choice_update(), is always valid
    BlockId last_finalized_head() const;
    BlockId current_head() const;

    // header/body retrieval
    BlockNum get_block_progress() const;
    std::optional<BlockHeader> get_header(BlockNum, Hash) const;
    std::optional<Hash> get_finalized_canonical_hash(BlockNum) const;
    std::optional<TotalDifficulty> get_header_td(BlockNum, Hash) const;
    std::vector<BlockHeader> get_last_headers(uint64_t limit) const;
    bool extends_last_fork_choice(BlockNum, Hash) const;
    bool extends(BlockId block, BlockId supposed_parent) const;
    bool is_finalized_canonical(Hash) const;
    // Warning: this getters use kHeaderNumbers so will return only header processed by the pipeline
    std::optional<BlockHeader> get_header(Hash) const;
    std::optional<TotalDifficulty> get_header_td(Hash) const;
    std::optional<BlockBody> get_body(Hash) const;
    std::optional<BlockNum> get_block_number(Hash) const;

    NodeSettings& node_settings();
    db::RWTxn& tx();  // only for testing purposes due to MDBX limitations

  protected:
    Hash insert_header(const BlockHeader&);
    void insert_body(const Block&, const Hash& block_hash);
    void forward(BlockNum head_height, const Hash& head_hash);
    void unwind(BlockNum unwind_point);

    bool is_canonical(BlockNum block_height, const Hash& block_hash) const;
    bool is_canonical_head_ancestor(const Hash& block_hash) const;

    std::set<Hash> collect_bad_headers(db::RWTxn& tx, InvalidChain& invalid_chain);

    boost::asio::io_context& io_context_;
    NodeSettings& node_settings_;
    mutable db::RWAccess db_access_;
    mutable db::RWTxnManaged tx_;
    db::DataModel data_model_;
    bool is_first_sync_{true};

    ExecutionPipeline pipeline_;
    CanonicalChain interim_canonical_chain_;
    VerificationResult interim_head_status_;
    BlockId last_fork_choice_;
    BlockId last_finalized_head_;
};

}  // namespace silkworm::stagedsync
