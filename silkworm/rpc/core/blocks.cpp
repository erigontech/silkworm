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

constexpr const char* kHeadBlockHash = "headBlockHash";
constexpr const char* kFinalizedBlockHash = "finalizedBlockHash";
constexpr const char* kSafeBlockHash = "safeBlockHash";

using namespace silkworm::db;
using namespace silkworm::db::chain;

static Task<BlockNum> get_forkchoice_block_number(kv::api::Transaction& tx, const char* block_hash_tag) {
    const auto kv_pair = co_await tx.get(table::kLastForkchoiceName, string_to_bytes(block_hash_tag));
    const auto block_hash_data = kv_pair.value;
    if (block_hash_data.empty()) {
        co_return 0;
    }
    const auto block_hash = to_bytes32(block_hash_data);
    co_return co_await read_header_number(tx, block_hash);
}

Task<bool> is_latest_block_number(BlockNum block_number, kv::api::Transaction& tx) {
    const auto last_executed_block_number = co_await get_latest_executed_block_number(tx);
    co_return last_executed_block_number == block_number;
}

Task<BlockNum> get_block_number_by_tag(const std::string& block_id, kv::api::Transaction& tx) {
    BlockNum block_number{0};
    if (block_id == kEarliestBlockId) {
        block_number = kEarliestBlockNumber;
    } else if (block_id == kLatestBlockId || block_id == kPendingBlockId) {  // NOLINT(bugprone-branch-clone)
        block_number = co_await get_latest_block_number(tx);
    } else if (block_id == kFinalizedBlockId) {
        block_number = co_await get_forkchoice_finalized_block_number(tx);
    } else if (block_id == kSafeBlockId) {
        block_number = co_await get_forkchoice_safe_block_number(tx);
    } else {
        block_number = co_await get_latest_executed_block_number(tx);
    }
    SILK_DEBUG << "get_block_number_by_tag block_number: " << block_number;
    co_return block_number;
}

Task<std::pair<BlockNum, bool>> get_block_number(const std::string& block_id, kv::api::Transaction& tx, bool latest_required) {
    BlockNum block_number{0};
    bool is_latest_block = false;
    bool check_if_latest = false;
    if (block_id == kEarliestBlockId) {
        block_number = kEarliestBlockNumber;
    } else if (block_id == kLatestBlockId || block_id == kPendingBlockId) {  // NOLINT(bugprone-branch-clone)
        block_number = co_await get_latest_block_number(tx);
        is_latest_block = true;
    } else if (block_id == kFinalizedBlockId) {  // NOLINT(bugprone-branch-clone)
        block_number = co_await get_forkchoice_finalized_block_number(tx);
        check_if_latest = latest_required;
    } else if (block_id == kSafeBlockId) {
        block_number = co_await get_forkchoice_safe_block_number(tx);
        check_if_latest = latest_required;
    } else if (block_id == kLatestExecutedBlockId) {
        block_number = co_await get_latest_executed_block_number(tx);
        is_latest_block = true;
    } else if (is_valid_hex(block_id)) {
        block_number = static_cast<BlockNum>(std::stol(block_id, nullptr, 16));
        check_if_latest = latest_required;
    } else {
        throw std::invalid_argument("get_block_number::Invalid Block Id");
    }

    if (check_if_latest) {
        is_latest_block = co_await is_latest_block_number(block_number, tx);
    }
    SILK_DEBUG << "get_block_number block_number: " << block_number << " is_latest_block: " << is_latest_block;
    co_return std::make_pair(block_number, is_latest_block);
}

Task<BlockNum> get_block_number(const std::string& block_id, kv::api::Transaction& tx) {
    const auto [block_number, _] = co_await get_block_number(block_id, tx, /*latest_required=*/false);
    co_return block_number;
}

Task<std::pair<BlockNum, bool>> get_block_number(const BlockNumberOrHash& bnoh, kv::api::Transaction& tx) {
    if (bnoh.is_tag()) {
        co_return co_await get_block_number(bnoh.tag(), tx, true);
    } else if (bnoh.is_number()) {
        co_return co_await get_block_number(to_hex(bnoh.number(), true), tx, true);
    } else if (bnoh.is_hash()) {
        const auto block_number = co_await read_header_number(tx, bnoh.hash());
        const auto latest_block_number = co_await get_latest_block_number(tx);
        co_return std::make_pair(block_number, block_number == latest_block_number);
    } else {
        throw std::invalid_argument("Invalid Block Number or Hash");
    }
}

Task<BlockNum> get_current_block_number(kv::api::Transaction& tx) {
    co_return co_await stages::get_sync_stage_progress(tx, stages::kFinish);
}

Task<BlockNum> get_highest_block_number(kv::api::Transaction& tx) {
    co_return co_await stages::get_sync_stage_progress(tx, stages::kHeaders);
}

Task<BlockNum> get_latest_executed_block_number(kv::api::Transaction& tx) {
    co_return co_await stages::get_sync_stage_progress(tx, stages::kExecution);
}

Task<BlockNum> get_latest_block_number(kv::api::Transaction& tx) {
    const auto kv_pair = co_await tx.get(table::kLastForkchoiceName, string_to_bytes(kHeadBlockHash));
    const auto head_block_hash_data = kv_pair.value;
    if (!head_block_hash_data.empty()) {
        const auto head_block_hash = to_bytes32(head_block_hash_data);
        co_return co_await read_header_number(tx, head_block_hash);
    }
    co_return co_await get_latest_executed_block_number(tx);
}

Task<BlockNum> get_forkchoice_finalized_block_number(kv::api::Transaction& tx) {
    co_return co_await get_forkchoice_block_number(tx, kFinalizedBlockHash);
}

Task<BlockNum> get_forkchoice_safe_block_number(kv::api::Transaction& tx) {
    co_return co_await get_forkchoice_block_number(tx, kSafeBlockHash);
}

Task<bool> is_latest_block_number(const BlockNumberOrHash& bnoh, kv::api::Transaction& tx) {
    if (bnoh.is_tag()) {
        co_return bnoh.tag() == core::kLatestBlockId || bnoh.tag() == core::kPendingBlockId;
    } else {
        const auto latest_block_number = co_await get_latest_block_number(tx);
        if (bnoh.is_number()) {
            co_return bnoh.number() == latest_block_number;
        } else {
            SILKWORM_ASSERT(bnoh.is_hash());
            const auto block_number = co_await read_header_number(tx, bnoh.hash());
            co_return block_number == latest_block_number;
        }
    }
}

}  // namespace silkworm::rpc::core
