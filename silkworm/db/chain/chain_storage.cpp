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

#include <utility>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/chain/chain.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/log.hpp>

using namespace silkworm::db;
using namespace silkworm::db::chain;

namespace silkworm::db::chain {

static constexpr const char* kHeadBlockHash = "headBlockHash";
static constexpr const char* kFinalizedBlockHash = "finalizedBlockHash";
static constexpr const char* kSafeBlockHash = "safeBlockHash";

Task<bool> ChainStorage::is_latest_block_num(BlockNum block_num) {
    const auto last_executed_block_num = co_await get_latest_executed_block_num();
    co_return last_executed_block_num == block_num;
}

Task<BlockNum> ChainStorage::get_block_num_by_tag(const std::string& block_id) {
    BlockNum block_num{0};
    if (block_id == kEarliestBlockId) {
        block_num = kEarliestBlockNum;
    } else if (block_id == kLatestBlockId || block_id == kPendingBlockId) {  // NOLINT(bugprone-branch-clone)
        block_num = co_await get_latest_block_num();
    } else if (block_id == kFinalizedBlockId) {
        block_num = co_await get_forkchoice_finalized_block_num();
    } else if (block_id == kSafeBlockId) {
        block_num = co_await get_forkchoice_safe_block_num();
    } else {
        block_num = co_await get_latest_executed_block_num();
    }
    SILK_DEBUG << "get_block_num_by_tag block_num: " << block_num;
    co_return block_num;
}

Task<std::pair<BlockNum, bool>> ChainStorage::get_block_num(const std::string& block_id, bool latest_required) {
    BlockNum block_num{0};
    bool is_latest_block = false;
    bool check_if_latest = false;
    if (block_id == kEarliestBlockId) {
        block_num = kEarliestBlockNum;
    } else if (block_id == kLatestBlockId || block_id == kPendingBlockId) {  // NOLINT(bugprone-branch-clone)
        block_num = co_await get_latest_block_num();
        is_latest_block = true;
    } else if (block_id == kFinalizedBlockId) {  // NOLINT(bugprone-branch-clone)
        block_num = co_await get_forkchoice_finalized_block_num();
        check_if_latest = latest_required;
    } else if (block_id == kSafeBlockId) {
        block_num = co_await get_forkchoice_safe_block_num();
        check_if_latest = latest_required;
    } else if (block_id == kLatestExecutedBlockId) {
        block_num = co_await get_latest_executed_block_num();
        is_latest_block = true;
    } else if (is_valid_hex(block_id)) {
        block_num = static_cast<BlockNum>(std::stol(block_id, nullptr, 16));
        check_if_latest = latest_required;
    } else {
        throw std::invalid_argument("get_block_num::Invalid Block Id");
    }

    if (check_if_latest) {
        is_latest_block = co_await is_latest_block_num(block_num);
    }
    SILK_DEBUG << "get_block_num block_num: " << block_num << " is_latest_block: " << is_latest_block;
    co_return std::make_pair(block_num, is_latest_block);
}

Task<BlockNum> ChainStorage::get_block_num(const std::string& block_id) {
    const auto [block_num, _] = co_await get_block_num(block_id, /*latest_required=*/false);
    co_return block_num;
}

Task<std::pair<BlockNum, bool>> ChainStorage::get_block_num(const BlockNumOrHash& block_num_or_hash) {
    if (block_num_or_hash.is_tag()) {
        co_return co_await get_block_num(block_num_or_hash.tag(), true);
    } else if (block_num_or_hash.is_number()) {
        co_return co_await get_block_num(to_hex(block_num_or_hash.number(), true), true);
    } else if (block_num_or_hash.is_hash()) {
        const auto block_num = co_await read_block_num(block_num_or_hash.hash());
        const auto latest_block_num = co_await get_latest_block_num();
        std::cout << "TODO: should not happen: " << *block_num << " " << latest_block_num << "\n";
        // co_return std::make_pair(block_num, block_num == latest_block_num); TODO
    } else {
        throw std::invalid_argument("Invalid Block Number or Hash");
    }
}

Task<BlockNum> ChainStorage::get_current_block_num() {
    co_return co_await get_sync_stage_progress(kFinish);
}

Task<BlockNum> ChainStorage::get_max_block_num() {
    co_return co_await get_sync_stage_progress(kHeaders);
}

Task<BlockNum> ChainStorage::get_latest_executed_block_num() {
    co_return co_await get_sync_stage_progress(kExecution);
}

Task<BlockNum> ChainStorage::get_forkchoice_finalized_block_num() {
    co_return co_await get_forkchoice_block_num(kFinalizedBlockHash);
}

Task<BlockNum> ChainStorage::get_forkchoice_safe_block_num() {
    co_return co_await get_forkchoice_block_num(kSafeBlockHash);
}

Task<bool> ChainStorage::is_latest_block_num(const BlockNumOrHash& block_num_or_hash) {
    if (block_num_or_hash.is_tag()) {
        co_return block_num_or_hash.tag() == kLatestBlockId || block_num_or_hash.tag() == kPendingBlockId;
    } else {
        const auto latest_block_num = co_await get_latest_block_num();
        if (block_num_or_hash.is_number()) {
            co_return block_num_or_hash.number() == latest_block_num;
        } else {
            SILKWORM_ASSERT(block_num_or_hash.is_hash());
            const auto block_num = co_await read_block_num(block_num_or_hash.hash());
            co_return block_num == latest_block_num;
        }
    }
}

Task<BlockNum> ChainStorage::get_latest_block_num() {
    std::cout << "empty:: ChainStorage::get_latest_block_num\n";

    // TODO
    /*

    const auto kv_pair = co_await tx.get(table::kLastForkchoiceName, string_to_bytes(kHeadBlockHash));
    const auto head_block_hash_data = kv_pair.value;
    if (!head_block_hash_data.empty()) {
        const auto head_block_hash = to_bytes32(head_block_hash_data);
        co_return co_await read_block_num(head_block_hash);
    }
    co_return co_await get_latest_executed_block_num();
*/
    co_return 0;
}

Task<BlockNum> ChainStorage::get_sync_stage_progress(const Bytes& /* stage_key */) {
    std::cout << "empty:: ChainStorage::get_sync_stage_progress\n";
    // TODO
    /*
    const auto kv_pair = co_await tx.get(db::table::kSyncStageProgressName, stage_key);
    const auto value = kv_pair.value;
    if (value.empty()) {
        co_return 0;
    }
    if (value.length() < 8) {
        throw std::runtime_error("data too short, expected 8 got " + std::to_string(value.length()));
    }
    BlockNum block_num = endian::load_big_u64(value.substr(0, 8).data());
    co_return block_num;

     */
    co_return 0;
}

Task<BlockNum> ChainStorage::get_forkchoice_block_num(const char* /*block_hash_tag */) {
    std::cout << "empty:: ChainStorage::get_forkchoice_block_num\n";

    // TODO
    /*
    const auto kv_pair = co_await tx.get(table::kLastForkchoiceName, string_to_bytes(block_hash_tag));
    const auto block_hash_data = kv_pair.value;
    if (block_hash_data.empty()) {
        co_return 0;
    }
    const auto block_hash = to_bytes32(block_hash_data);
    co_return co_await read_block_num(block_hash);

     */
    co_return 0;
}

}  // namespace silkworm::db::chain
