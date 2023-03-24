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
#include <silkworm/node/stagedsync/stage.hpp>

namespace silkworm::stagedsync {

class ExecutionEngine : public Stoppable {
  public:
    explicit ExecutionEngine(NodeSettings&, db::RWAccess);

    struct ValidChain {
        BlockNum current_point;
    };
    struct InvalidChain {
        BlockNum unwind_point;
        Hash unwind_head;
        std::optional<Hash> bad_block;
        std::set<Hash> bad_headers;
    };
    struct ValidationError {
        BlockNum last_point;
    };
    using VerificationResult = std::variant<ValidChain, InvalidChain, ValidationError>;

    // actions
    template <std::derived_from<Block> BLOCK>
    void insert_blocks(std::vector<std::shared_ptr<BLOCK>>& blocks);
    void insert_block(const Block& block);

    auto verify_chain(Hash head_block_hash) -> VerificationResult;

    bool notify_fork_choice_update(Hash head_block_hash, std::optional<Hash> finalized_block_hash = std::nullopt);

    // state
    auto current_status() -> VerificationResult;
    auto last_fork_choice() -> BlockId;

    auto get_canonical_head() -> ChainHead;  // todo: must return the last FCU

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
    void insert_header(const BlockHeader&);
    void insert_body(const Block&);

    std::set<Hash> collect_bad_headers(db::RWTxn& tx, InvalidChain& invalid_chain);

    class CanonicalChain {
      public:
        explicit CanonicalChain(db::RWTxn&);

        BlockNum find_forking_point(db::RWTxn& tx, Hash header_hash);

        void update_up_to(BlockNum height, Hash header_hash);
        void delete_down_to(BlockNum unwind_point);

        BlockId initial_head();
        BlockId current_head();

        auto get_hash(BlockNum height) -> std::optional<Hash>;

      private:
        db::RWTxn& tx_;

        BlockId initial_head_{};
        BlockId current_head_{};

        static constexpr size_t kCacheSize = 1000;
        lru_cache<BlockNum, Hash> canonical_cache_;
    };

    NodeSettings& node_settings_;
    db::RWAccess db_access_;
    db::RWTxn tx_;
    bool is_first_sync_{true};
    // lru_cache<Hash, BlockHeader> header_cache_;  // use cache if it improves performances

    ExecutionPipeline pipeline_;

    CanonicalChain canonical_chain_;
    VerificationResult canonical_status_;
    BlockId last_fork_choice_;
};

template <std::derived_from<Block> BLOCK>
void ExecutionEngine::insert_blocks(std::vector<std::shared_ptr<BLOCK>>& blocks) {
    SILK_TRACE << "ExecutionEngine: inserting " << blocks.size() << " blocks";
    if (blocks.empty()) return;

    as_range::for_each(blocks, [&, this](const auto& block) {
        insert_header(block->header);
        insert_body(*block);
    });

    if (is_first_sync_) tx_.commit_and_renew();
}

}  // namespace silkworm::stagedsync
