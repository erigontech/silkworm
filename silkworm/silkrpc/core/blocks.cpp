/*
    Copyright 2020 The Silkrpc Authors

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

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>
#include <silkworm/silkrpc/stagedsync/stages.hpp>
#include <silkworm/silkrpc/ethdb/tables.hpp>
#include <silkworm/core/common/assert.hpp>

namespace silkrpc::core {

constexpr const char* kHeadBlockHash = "headBlockHash";
constexpr const char* kFinalizedBlockHash = "finalizedBlockHash";
constexpr const char* kSafeBlockHash = "safeBlockHash";


boost::asio::awaitable<bool> is_latest_block_number(uint64_t block_number, const core::rawdb::DatabaseReader& db_reader) {
    const auto last_executed_block_number = co_await core::get_latest_executed_block_number(db_reader);
    co_return last_executed_block_number == block_number;
}

boost::asio::awaitable<uint64_t> get_block_number_by_tag(const std::string& block_id, const core::rawdb::DatabaseReader& reader) {
    uint64_t  block_number;
    if (block_id == kEarliestBlockId) {
        block_number = kEarliestBlockNumber;
    } else if (block_id == kLatestBlockId || block_id == kPendingBlockId) {
        block_number = co_await get_latest_block_number(reader);
    } else if (block_id == kFinalizedBlockId) {
        block_number = co_await get_forkchoice_finalized_block_number(reader);
    } else if (block_id == kSafeBlockId) {
        block_number = co_await get_forkchoice_safe_block_number(reader);
    } else {
        block_number = co_await get_latest_executed_block_number(reader);
    }
    SILKRPC_DEBUG << "get_block_number_by_tag block_number: " << block_number << "\n";
    co_return block_number;
}

boost::asio::awaitable<std::pair<uint64_t, bool>> get_block_number(const std::string& block_id, const core::rawdb::DatabaseReader& reader, bool latest_required) {
    uint64_t  block_number;
    bool is_latest_block = false;
    bool check_if_latest = false;
    if (block_id == kEarliestBlockId) {
        block_number = kEarliestBlockNumber;
    } else if (block_id == kLatestBlockId || block_id == kPendingBlockId) {
        block_number = co_await get_latest_block_number(reader);
        is_latest_block = true;
    } else if (block_id == kFinalizedBlockId) {
        block_number = co_await get_forkchoice_finalized_block_number(reader);
        check_if_latest = latest_required;
    } else if (block_id == kSafeBlockId) {
        block_number = co_await get_forkchoice_safe_block_number(reader);
        check_if_latest = latest_required;
    } else if (block_id == kLatestExecutedBlockId) {
        block_number = co_await get_latest_executed_block_number(reader);
        is_latest_block = true;
    } else {
        block_number = std::stol(block_id, 0, 0);
        check_if_latest = latest_required;
    }
    if (check_if_latest) {
        is_latest_block = co_await is_latest_block_number(block_number, reader);
    }
    SILKRPC_DEBUG << "get_block_number block_number: " << block_number << " is_latest_block: " << is_latest_block << "\n";
    co_return std::make_pair(block_number, is_latest_block);
}

boost::asio::awaitable<uint64_t> get_block_number(const std::string& block_id, const core::rawdb::DatabaseReader& reader) {
   const auto [block_number, _] = co_await get_block_number(block_id, reader, /*latest_required=*/false);
   co_return block_number;
}

boost::asio::awaitable<uint64_t> get_current_block_number(const core::rawdb::DatabaseReader& reader) {
    const auto current_block_number = co_await stages::get_sync_stage_progress(reader, stages::kFinish);
    co_return current_block_number;
}

boost::asio::awaitable<uint64_t> get_highest_block_number(const core::rawdb::DatabaseReader& reader) {
    const auto highest_block_number = co_await stages::get_sync_stage_progress(reader, stages::kHeaders);
    co_return highest_block_number;
}

boost::asio::awaitable<uint64_t> get_latest_executed_block_number(const core::rawdb::DatabaseReader& reader) {
    const auto latest_executed_block_number = co_await stages::get_sync_stage_progress(reader, stages::kExecution);
    co_return latest_executed_block_number;
}

boost::asio::awaitable<uint64_t> get_latest_block_number(const core::rawdb::DatabaseReader& reader) {
    const auto kv_pair = co_await reader.get(db::table::kLastForkchoice, silkworm::bytes_of_string(kHeadBlockHash));
    const auto head_block_hash_data = kv_pair.value;
    if (!head_block_hash_data.empty()) {
        const auto head_block_hash = silkworm::to_bytes32(head_block_hash_data);
        const silkworm::BlockHeader head_block_header = co_await rawdb::read_header_by_hash(reader, head_block_hash);
        co_return head_block_header.number;
    }

    const auto latest_block_number = co_await stages::get_sync_stage_progress(reader, stages::kExecution);
    co_return latest_block_number;
}

boost::asio::awaitable<uint64_t> get_forkchoice_finalized_block_number(const core::rawdb::DatabaseReader& reader) {
    const auto kv_pair = co_await reader.get(db::table::kLastForkchoice, silkworm::bytes_of_string(kFinalizedBlockHash));
    const auto finalized_block_hash_data = kv_pair.value;
    if (finalized_block_hash_data.empty()) {
        SILKRPC_LOG << "no finalized forkchoice block number found\n";
        co_return 0;
    }
    const auto finalized_block_hash = silkworm::to_bytes32(finalized_block_hash_data);

    const auto finalized_header = co_await rawdb::read_header_by_hash(reader, finalized_block_hash);
    co_return finalized_header.number;
}

boost::asio::awaitable<uint64_t> get_forkchoice_safe_block_number(const core::rawdb::DatabaseReader& reader) {
    const auto kv_pair = co_await reader.get(db::table::kLastForkchoice, silkworm::bytes_of_string(kSafeBlockHash));
    const auto safe_block_hash_data = kv_pair.value;
    if (safe_block_hash_data.empty()) {
        SILKRPC_LOG << "no safe forkchoice block number found\n";
        co_return 0;
    }
    const auto safe_block_hash = silkworm::to_bytes32(safe_block_hash_data);

    const silkworm::BlockHeader safe_block_header = co_await rawdb::read_header_by_hash(reader, safe_block_hash);
    co_return safe_block_header.number;
}

boost::asio::awaitable<bool> is_latest_block_number(const BlockNumberOrHash& bnoh, const core::rawdb::DatabaseReader& reader) {
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

}  // namespace silkrpc::core
