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

#include "blocks.hpp"

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/chain/chain.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/stagedsync/stages.hpp>

namespace silkworm::rpc::core {

static constexpr const char* kHeadBlockHash = "headBlockHash";
static constexpr const char* kFinalizedBlockHash = "finalizedBlockHash";
static constexpr const char* kSafeBlockHash = "safeBlockHash";

using namespace silkworm::db;
using namespace silkworm::db::chain;

static Task<BlockNum> get_forkchoice_block_num(kv::api::Transaction& tx, const char* block_hash_tag) {
    const auto kv_pair = co_await tx.get(table::kLastForkchoiceName, string_to_bytes(block_hash_tag));
    const auto block_hash_data = kv_pair.value;
    if (block_hash_data.empty()) {
        co_return 0;
    }
    const auto block_hash = to_bytes32(block_hash_data);
    co_return co_await read_header_number(tx, block_hash);
}

Task<bool> is_latest_block_num(BlockNum block_num, kv::api::Transaction& tx) {
    const auto last_executed_block_num = co_await get_latest_executed_block_num(tx);
    co_return last_executed_block_num == block_num;
}

Task<BlockNum> get_block_num_by_tag(const std::string& block_id, kv::api::Transaction& tx) {
    BlockNum block_num{0};
    if (block_id == kEarliestBlockId) {
        block_num = kEarliestBlockNum;
    } else if (block_id == kLatestBlockId || block_id == kPendingBlockId) {  // NOLINT(bugprone-branch-clone)
        block_num = co_await get_latest_block_num(tx);
    } else if (block_id == kFinalizedBlockId) {
        block_num = co_await get_forkchoice_finalized_block_num(tx);
    } else if (block_id == kSafeBlockId) {
        block_num = co_await get_forkchoice_safe_block_num(tx);
    } else {
        block_num = co_await get_latest_executed_block_num(tx);
    }
    SILK_DEBUG << "get_block_num_by_tag block_num: " << block_num;
    co_return block_num;
}

Task<std::pair<BlockNum, bool>> get_block_num(const std::string& block_id, kv::api::Transaction& tx, bool latest_required) {
    BlockNum block_num{0};
    bool is_latest_block = false;
    bool check_if_latest = false;
    if (block_id == kEarliestBlockId) {
        block_num = kEarliestBlockNum;
    } else if (block_id == kLatestBlockId || block_id == kPendingBlockId) {  // NOLINT(bugprone-branch-clone)
        block_num = co_await get_latest_block_num(tx);
        is_latest_block = true;
    } else if (block_id == kFinalizedBlockId) {  // NOLINT(bugprone-branch-clone)
        block_num = co_await get_forkchoice_finalized_block_num(tx);
        check_if_latest = latest_required;
    } else if (block_id == kSafeBlockId) {
        block_num = co_await get_forkchoice_safe_block_num(tx);
        check_if_latest = latest_required;
    } else if (block_id == kLatestExecutedBlockId) {
        block_num = co_await get_latest_executed_block_num(tx);
        is_latest_block = true;
    } else if (is_valid_hex(block_id)) {
        block_num = static_cast<BlockNum>(std::stol(block_id, nullptr, 16));
        check_if_latest = latest_required;
    } else {
        throw std::invalid_argument("get_block_num::Invalid Block Id");
    }

    if (check_if_latest) {
        is_latest_block = co_await is_latest_block_num(block_num, tx);
    }
    SILK_DEBUG << "get_block_num block_num: " << block_num << " is_latest_block: " << is_latest_block;
    co_return std::make_pair(block_num, is_latest_block);
}

Task<BlockNum> get_block_num(const std::string& block_id, kv::api::Transaction& tx) {
    const auto [block_num, _] = co_await get_block_num(block_id, tx, /*latest_required=*/false);
    co_return block_num;
}

Task<std::pair<BlockNum, bool>> get_block_num(const BlockNumberOrHash& block_num_or_hash, kv::api::Transaction& tx) {
    if (block_num_or_hash.is_tag()) {
        co_return co_await get_block_num(block_num_or_hash.tag(), tx, true);
    } else if (block_num_or_hash.is_number()) {
        co_return co_await get_block_num(to_hex(block_num_or_hash.number(), true), tx, true);
    } else if (block_num_or_hash.is_hash()) {
        const auto block_num = co_await read_header_number(tx, block_num_or_hash.hash());
        const auto latest_block_num = co_await get_latest_block_num(tx);
        co_return std::make_pair(block_num, block_num == latest_block_num);
    } else {
        throw std::invalid_argument("Invalid Block Number or Hash");
    }
}

Task<BlockNum> get_current_block_num(kv::api::Transaction& tx) {
    co_return co_await stages::get_sync_stage_progress(tx, stages::kFinish);
}

Task<BlockNum> get_max_block_num(kv::api::Transaction& tx) {
    co_return co_await stages::get_sync_stage_progress(tx, stages::kHeaders);
}

Task<BlockNum> get_latest_executed_block_num(kv::api::Transaction& tx) {
    co_return co_await stages::get_sync_stage_progress(tx, stages::kExecution);
}

Task<BlockNum> get_latest_block_num(kv::api::Transaction& tx) {
    const auto kv_pair = co_await tx.get(table::kLastForkchoiceName, string_to_bytes(kHeadBlockHash));
    const auto head_block_hash_data = kv_pair.value;
    if (!head_block_hash_data.empty()) {
        const auto head_block_hash = to_bytes32(head_block_hash_data);
        co_return co_await read_header_number(tx, head_block_hash);
    }
    co_return co_await get_latest_executed_block_num(tx);
}

Task<BlockNum> get_forkchoice_finalized_block_num(kv::api::Transaction& tx) {
    co_return co_await get_forkchoice_block_num(tx, kFinalizedBlockHash);
}

Task<BlockNum> get_forkchoice_safe_block_num(kv::api::Transaction& tx) {
    co_return co_await get_forkchoice_block_num(tx, kSafeBlockHash);
}

Task<bool> is_latest_block_num(const BlockNumberOrHash& block_num_or_hash, kv::api::Transaction& tx) {
    if (block_num_or_hash.is_tag()) {
        co_return block_num_or_hash.tag() == core::kLatestBlockId || block_num_or_hash.tag() == core::kPendingBlockId;
    } else {
        const auto latest_block_num = co_await get_latest_block_num(tx);
        if (block_num_or_hash.is_number()) {
            co_return block_num_or_hash.number() == latest_block_num;
        } else {
            SILKWORM_ASSERT(block_num_or_hash.is_hash());
            const auto block_num = co_await read_header_number(tx, block_num_or_hash.hash());
            co_return block_num == latest_block_num;
        }
    }
}

}  // namespace silkworm::rpc::core
