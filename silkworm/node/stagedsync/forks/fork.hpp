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

    // verification result | clang-format off
    struct ValidChain {
        BlockId current_head;
    };
    struct InvalidChain {
        BlockId unwind_point;
        std::optional<Hash> bad_block;
        std::set<Hash> bad_headers;
    };
    struct ValidationError {
        BlockId latest_valid_head;
    };
    using VerificationResult = std::variant<ValidChain, InvalidChain, ValidationError>;  // clang-format on

    // actions
    void insert_block_over_head(const Block& block);

    auto verify_chain(Hash head_block_hash) -> VerificationResult;

    bool notify_fork_choice_update(Hash head_block_hash, std::optional<Hash> finalized_block_hash = std::nullopt);

    // state
    auto current_head() -> BlockId;

    auto last_verified_head() -> BlockId;
    auto last_head_status() -> VerificationResult;

    bool extends_current_head(const BlockHeader&);

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

}  // namespace silkworm::stagedsync
