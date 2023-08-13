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

#include <boost/asio.hpp>

#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/node/db/memory_mutation.hpp>
#include <silkworm/node/stagedsync/execution_pipeline.hpp>
#include <silkworm/node/stagedsync/stages/stage.hpp>

#include "canonical_chain.hpp"
#include "verification_result.hpp"

namespace silkworm::stagedsync {

namespace asio = boost::asio;

class Fork;
class ExtendingFork;

class MainChain {
  public:
    explicit MainChain(asio::io_context&, NodeSettings&, db::RWAccess);

    void open();  // needed to circumvent mdbx threading model limitations
    void close();

    // extension
    void insert_block(const Block&);

    // branching
    auto fork(BlockId forking_point) -> std::unique_ptr<ExtendingFork>;  // fort at the current head
    void reintegrate_fork(ExtendingFork&);                               // reintegrate fork into the main chain
    auto find_forking_point(const BlockHeader& header, const Hash& header_hash) const -> std::optional<BlockId>;
    auto find_forking_point(const Hash& header_hash) const -> std::optional<BlockId>;
    auto is_canonical(BlockId block) const -> bool;

    // verification
    auto verify_chain(Hash head_block_hash) -> VerificationResult;  // verify chain up to head_block_hash
    bool notify_fork_choice_update(Hash head_block_hash,            // accept the current chain up to head_block_hash
                                   std::optional<Hash> finalized_block_hash = std::nullopt);

    // state
    auto last_chosen_head() const -> BlockId;  // set by notify_fork_choice_update(), is always valid
    auto last_finalized_head() const -> BlockId;

    // header/body retrieval
    auto get_block_progress() const -> BlockNum;
    auto get_header(BlockNum, Hash) const -> std::optional<BlockHeader>;
    auto get_canonical_hash(BlockNum) const -> std::optional<Hash>;
    auto get_header_td(BlockNum, Hash) const -> std::optional<TotalDifficulty>;
    auto get_last_headers(uint64_t limit) const -> std::vector<BlockHeader>;
    auto extends_last_fork_choice(BlockNum, Hash) const -> bool;
    auto extends(BlockId block, BlockId supposed_parent) const -> bool;
    auto is_ancestor(BlockId supposed_parent, BlockId block) const -> bool;
    auto is_canonical(Hash) const -> bool;
    // Warning: this getters use kHeaderNumbers so will return only header processed by the pipeline
    auto get_header(Hash) const -> std::optional<BlockHeader>;
    auto get_header_td(Hash) const -> std::optional<TotalDifficulty>;
    auto get_body(Hash) const -> std::optional<BlockBody>;
    auto get_block_number(Hash) const -> std::optional<BlockNum>;

    NodeSettings& node_settings();
    db::RWTxn& tx();  // only for testing purposes due to MDBX limitations

  protected:
    Hash insert_header(const BlockHeader&);
    void insert_body(const Block&, const Hash& block_hash);

    auto current_head() const -> BlockId;  // private state, it is implementation dependent, this head can be invalid

    std::set<Hash> collect_bad_headers(db::RWTxn& tx, InvalidChain& invalid_chain);

    asio::io_context& io_context_;
    NodeSettings& node_settings_;
    db::RWAccess db_access_;
    mutable db::RWTxnManaged tx_;
    db::DataModel data_model_;
    bool is_first_sync_{true};

    ExecutionPipeline pipeline_;
    CanonicalChain canonical_chain_;
    VerificationResult canonical_head_status_;
    BlockId last_fork_choice_;
    BlockId last_finalized_head_;
};

}  // namespace silkworm::stagedsync
