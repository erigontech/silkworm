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

#include <silkworm/rpc/ethdb/transaction.hpp>
#include <silkworm/rpc/types/block.hpp>

namespace silkworm::rpc::core {

constexpr const char* kEarliestBlockId{"earliest"};
constexpr const char* kLatestBlockId{"latest"};
constexpr const char* kPendingBlockId{"pending"};
constexpr const char* kFinalizedBlockId{"finalized"};
constexpr const char* kSafeBlockId{"safe"};
constexpr const char* kLatestExecutedBlockId{"latestExecuted"};

// TODO(canepat) migrate to ChainStorage?

Task<bool> is_latest_block_number(BlockNum block_number, ethdb::Transaction& tx);

Task<BlockNum> get_block_number_by_tag(const std::string& block_id, ethdb::Transaction& tx);

Task<std::pair<BlockNum, bool>> get_block_number(const std::string& block_id, ethdb::Transaction& tx, bool latest_required);

Task<BlockNum> get_block_number(const std::string& block_id, ethdb::Transaction& tx);

Task<std::pair<BlockNum, bool>> get_block_number(const BlockNumberOrHash& bnoh, ethdb::Transaction& tx);

Task<BlockNum> get_current_block_number(ethdb::Transaction& tx);

Task<BlockNum> get_highest_block_number(ethdb::Transaction& tx);

Task<BlockNum> get_latest_block_number(ethdb::Transaction& tx);

Task<BlockNum> get_latest_executed_block_number(ethdb::Transaction& tx);

Task<BlockNum> get_forkchoice_finalized_block_number(ethdb::Transaction& tx);

Task<BlockNum> get_forkchoice_safe_block_number(ethdb::Transaction& tx);

Task<bool> is_latest_block_number(const BlockNumberOrHash& bnoh, ethdb::Transaction& tx);

}  // namespace silkworm::rpc::core
