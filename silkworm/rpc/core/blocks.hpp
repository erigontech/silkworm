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

#include <string>
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/types/block.hpp>

namespace silkworm::rpc::core {

inline constexpr const char* kEarliestBlockId{"earliest"};
inline constexpr const char* kLatestBlockId{"latest"};
inline constexpr const char* kPendingBlockId{"pending"};
inline constexpr const char* kFinalizedBlockId{"finalized"};
inline constexpr const char* kSafeBlockId{"safe"};
inline constexpr const char* kLatestExecutedBlockId{"latestExecuted"};

// TODO(canepat) migrate to ChainStorage?

Task<bool> is_latest_block_num(BlockNum block_num, db::kv::api::Transaction& tx);

Task<BlockNum> get_block_num_by_tag(const std::string& block_id, db::kv::api::Transaction& tx);

Task<std::pair<BlockNum, bool>> get_block_num(const std::string& block_id, db::kv::api::Transaction& tx, bool latest_required);

Task<BlockNum> get_block_num(const std::string& block_id, db::kv::api::Transaction& tx);

Task<std::pair<BlockNum, bool>> get_block_num(const BlockNumberOrHash& block_num_or_hash, db::kv::api::Transaction& tx);

Task<BlockNum> get_current_block_num(db::kv::api::Transaction& tx);

Task<BlockNum> get_max_block_num(db::kv::api::Transaction& tx);

Task<BlockNum> get_latest_block_num(db::kv::api::Transaction& tx);

Task<BlockNum> get_latest_executed_block_num(db::kv::api::Transaction& tx);

Task<BlockNum> get_forkchoice_finalized_block_num(db::kv::api::Transaction& tx);

Task<BlockNum> get_forkchoice_safe_block_num(db::kv::api::Transaction& tx);

Task<bool> is_latest_block_num(const BlockNumberOrHash& block_num_or_hash, db::kv::api::Transaction& tx);

}  // namespace silkworm::rpc::core
