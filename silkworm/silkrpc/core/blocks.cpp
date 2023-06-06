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
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/db/tables.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>
#include <silkworm/silkrpc/stagedsync/stages.hpp>

namespace silkworm::rpc::core {

constexpr const char* kHeadBlockHash = "headBlockHash";
constexpr const char* kFinalizedBlockHash = "finalizedBlockHash";
constexpr const char* kSafeBlockHash = "safeBlockHash";

static boost::asio::awaitable<uint64_t> get_forkchoice_block_number(const rawdb::DatabaseReader& reader, const char* block_hash_tag) {
    const auto kv_pair = co_await reader.get(db::table::kLastForkchoiceName, bytes_of_string(block_hash_tag));
    const auto block_hash_data = kv_pair.value;
    if (block_hash_data.empty()) {
        co_return 0;
    }
    const auto block_hash = to_bytes32(block_hash_data);
    co_return co_await rawdb::read_header_number(reader, block_hash);
}

boost::asio::awaitable<bool> is_latest_block_number(uint64_t block_number, const rawdb::DatabaseReader& db_reader) {
    const auto last_executed_block_number = co_await get_latest_executed_block_number(db_reader);
    co_return last_executed_block_number == block_number;
}

boost::asio::awaitable<uint64_t> get_block_number_by_tag(const std::string& block_id, const rawdb::DatabaseReader& reader) {
    uint64_t block_number;
    if (block_id == kEarliestBlockId) {
        block_number = kEarliestBlockNumber;
    } else if (block_id == kLatestBlockId || block_id == kPendingBlockId) {  // NOLINT(bugprone-branch-clone)
        block_number = co_await get_latest_block_number(reader);
    } else if (block_id == kFinalizedBlockId) {
        block_number = co_await get_forkchoice_finalized_block_number(reader);
    } else if (block_id == kSafeBlockId) {
        block_number = co_await get_forkchoice_safe_block_number(reader);
    } else {
        block_number = co_await get_latest_executed_block_number(reader);
    }
    SILK_DEBUG << "get_block_number_by_tag block_number: " << block_number;
    co_return block_number;
}

boost::asio::awaitable<std::pair<uint64_t, bool>> get_block_number(const std::string& block_id, const rawdb::DatabaseReader& reader, bool latest_required) {
    uint64_t block_number;
    bool is_latest_block = false;
    bool check_if_latest = false;
    if (block_id == kEarliestBlockId) {
        block_number = kEarliestBlockNumber;
    } else if (block_id == kLatestBlockId || block_id == kPendingBlockId) {  // NOLINT(bugprone-branch-clone)
        block_number = co_await get_latest_block_number(reader);
        is_latest_block = true;
    } else if (block_id == kFinalizedBlockId) {  // NOLINT(bugprone-branch-clone)
        block_number = co_await get_forkchoice_finalized_block_number(reader);
        check_if_latest = latest_required;
    } else if (block_id == kSafeBlockId) {
        block_number = co_await get_forkchoice_safe_block_number(reader);
        check_if_latest = latest_required;
    } else if (block_id == kLatestExecutedBlockId) {
        block_number = co_await get_latest_executed_block_number(reader);
        is_latest_block = true;
    } else {
        block_number = static_cast<uint64_t>(std::stol(block_id, nullptr, 0));
        check_if_latest = latest_required;
    }
    if (check_if_latest) {
        is_latest_block = co_await is_latest_block_number(block_number, reader);
    }
    SILK_DEBUG << "get_block_number block_number: " << block_number << " is_latest_block: " << is_latest_block;
    co_return std::make_pair(block_number, is_latest_block);
}

boost::asio::awaitable<uint64_t> get_block_number(const std::string& block_id, const rawdb::DatabaseReader& reader) {
    const auto [block_number, _] = co_await get_block_number(block_id, reader, /*latest_required=*/false);
    co_return block_number;
}

boost::asio::awaitable<uint64_t> get_current_block_number(const rawdb::DatabaseReader& reader) {
    co_return co_await stages::get_sync_stage_progress(reader, stages::kFinish);
}

boost::asio::awaitable<uint64_t> get_highest_block_number(const rawdb::DatabaseReader& reader) {
    co_return co_await stages::get_sync_stage_progress(reader, stages::kHeaders);
}

boost::asio::awaitable<uint64_t> get_latest_executed_block_number(const rawdb::DatabaseReader& reader) {
    co_return co_await stages::get_sync_stage_progress(reader, stages::kExecution);
}

boost::asio::awaitable<uint64_t> get_latest_block_number(const rawdb::DatabaseReader& reader) {
    const auto kv_pair = co_await reader.get(db::table::kLastForkchoiceName, bytes_of_string(kHeadBlockHash));
    const auto head_block_hash_data = kv_pair.value;
    if (!head_block_hash_data.empty()) {
        const auto head_block_hash = to_bytes32(head_block_hash_data);
        co_return co_await rawdb::read_header_number(reader, head_block_hash);
    }
    co_return co_await get_latest_executed_block_number(reader);
}

boost::asio::awaitable<uint64_t> get_forkchoice_finalized_block_number(const rawdb::DatabaseReader& reader) {
    co_return co_await get_forkchoice_block_number(reader, kFinalizedBlockHash);
}

boost::asio::awaitable<uint64_t> get_forkchoice_safe_block_number(const rawdb::DatabaseReader& reader) {
    co_return co_await get_forkchoice_block_number(reader, kSafeBlockHash);
}

boost::asio::awaitable<bool> is_latest_block_number(const BlockNumberOrHash& bnoh, const rawdb::DatabaseReader& reader) {
    if (bnoh.is_tag()) {
        co_return bnoh.tag() == core::kLatestBlockId || bnoh.tag() == core::kPendingBlockId;
    } else {
        const auto latest_block_number = co_await get_latest_block_number(reader);
        if (bnoh.is_number()) {
            co_return bnoh.number() == latest_block_number;
        } else {
            SILKWORM_ASSERT(bnoh.is_hash());
            const auto block_number = co_await rawdb::read_header_number(reader, bnoh.hash());
            co_return block_number == latest_block_number;
        }
    }
}

}  // namespace silkworm::rpc::core
