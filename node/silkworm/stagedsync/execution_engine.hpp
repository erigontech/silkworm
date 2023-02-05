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
#include <set>
#include <variant>
#include <vector>

#include <silkworm/common/asio_timer.hpp>
#include <silkworm/common/lru_cache.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/downloader/internals/types.hpp>
#include <silkworm/stagedsync/stage.hpp>

#include "execution_pipeline.hpp"

/* clang-format off */

namespace silkworm::stagedsync {

class ExecutionEngine : public Stoppable {
  public:
    explicit ExecutionEngine(NodeSettings&, const db::RWAccess);
    ~ExecutionEngine() = default;

    struct ValidChain {BlockNum current_point;};
    struct InvalidChain {BlockNum unwind_point; Hash unwind_head; std::optional<Hash> bad_block; std::set<Hash> bad_headers;};
    struct ValidationError {BlockNum last_point;};
    using VerificationResult = std::variant<ValidChain, InvalidChain, ValidationError>;

    // actions
    template <typename BLOCK>
    requires std::is_base_of_v<Block, BLOCK>
    void insert_blocks(std::vector<std::shared_ptr<BLOCK>>&);


    auto verify_chain(Hash head_block_hash) -> VerificationResult;

    bool notify_fork_choice_updated(Hash head_block_hash);

    // state
    VerificationResult current_status();
    auto get_canonical_head() -> ChainHead;
    auto get_block_progress() -> BlockNum;

    auto get_header(Hash) -> std::optional<BlockHeader>;
    auto get_header(BlockNum, Hash) -> std::optional<BlockHeader>;
    auto get_canonical_hash(BlockNum) -> std::optional<Hash>;
    auto get_header_td(BlockNum, Hash) -> std::optional<Total_Difficulty>;
    auto get_body(Hash) -> std::optional<BlockBody>;
    auto get_last_headers(BlockNum limit) -> std::vector<BlockHeader>;

  protected:
    void insert_header(const BlockHeader&);
    void insert_body(const Block&);
    void insert_block(const Block& block);

    std::set<Hash> collect_bad_headers(db::RWTxn& tx, InvalidChain& invalid_chain);

    NodeSettings& node_settings_;
    db::RWAccess db_access_;
    db::RWTxn tx_;
    ExecutionPipeline pipeline_;
    bool is_first_sync{true};
    VerificationResult current_status_;
    // lru_cache<Hash, BlockHeader> header_cache_; // todo: use cache if improve performances

    class CanonicalChain {
      public:
        CanonicalChain(db::RWTxn&);

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
    } canonical_chain_;
};
}  // namespace silkworm::stagedsync
