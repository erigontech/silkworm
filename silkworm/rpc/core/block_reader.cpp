// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "block_reader.hpp"

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/db/kv/state_reader.hpp>
#include <silkworm/db/state/account_codec.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/json/types.hpp>
#include <silkworm/rpc/stagedsync/stages.hpp>

namespace silkworm::rpc {

using db::kv::StateReader;
using namespace silkworm::db;
using namespace silkworm::db::chain;

static constexpr const char* kHeadBlockHash = "headBlockHash";
static constexpr const char* kFinalizedBlockHash = "finalizedBlockHash";
static constexpr const char* kSafeBlockHash = "safeBlockHash";

void to_json(nlohmann::json& json, const BalanceChanges& balance_changes) {
    for (const auto& entry : balance_changes) {
        json[address_to_hex(entry.first)] = to_quantity(entry.second);
    }
}

Task<std::shared_ptr<BlockWithHash>> BlockReader::read_block_by_number(BlockCache& cache, BlockNum block_num) const {
    const auto block_hash = co_await chain_storage_.read_canonical_header_hash(block_num);
    if (!block_hash) {
        co_return nullptr;
    }
    const auto cached_block = cache.get(*block_hash);
    if (cached_block) {
        co_return cached_block.value();
    }
    const auto block_with_hash = std::make_shared<BlockWithHash>();
    const auto block_found = co_await chain_storage_.read_block(block_hash->bytes, block_num, /*read_senders=*/true, block_with_hash->block);
    if (!block_found) {
        co_return nullptr;
    }
    block_with_hash->hash = *block_hash;
    if (!block_with_hash->block.transactions.empty()) {
        // don't save empty (without txs) blocks to cache, if block become non-canonical (not in main chain), we remove it's transactions,
        // but block can in the future become canonical(inserted in main chain) with its transactions
        cache.insert(*block_hash, block_with_hash);
    }
    co_return block_with_hash;
}

Task<std::shared_ptr<BlockWithHash>> BlockReader::read_block_by_hash(BlockCache& cache, const evmc::bytes32& block_hash) const {
    const auto cached_block = cache.get(block_hash);
    if (cached_block) {
        co_return cached_block.value();
    }
    const auto block_with_hash = std::make_shared<BlockWithHash>();
    const auto block_num = co_await chain_storage_.read_block_num(block_hash);
    if (!block_num) {
        co_return nullptr;
    }
    const auto block_found = co_await chain_storage_.read_block(block_hash.bytes, *block_num, /*read_senders=*/true, block_with_hash->block);
    if (!block_found) {
        co_return nullptr;
    }
    block_with_hash->hash = block_hash;
    if (!block_with_hash->block.transactions.empty()) {
        // don't save empty (without txs) blocks to cache, if block become non-canonical (not in main chain), we remove it's transactions,
        // but block can in the future become canonical(inserted in main chain) with its transactions
        cache.insert(block_hash, block_with_hash);
    }
    co_return block_with_hash;
}

Task<std::shared_ptr<BlockWithHash>> BlockReader::read_block_by_block_num_or_hash(BlockCache& cache, const BlockNumOrHash& block_num_or_hash) const {
    if (block_num_or_hash.is_number()) {  // NOLINT(bugprone-branch-clone)
        co_return co_await read_block_by_number(cache, block_num_or_hash.number());
    }
    if (block_num_or_hash.is_hash()) {
        co_return co_await read_block_by_hash(cache, block_num_or_hash.hash());
    }
    if (block_num_or_hash.is_tag()) {
        auto [block_num, ignore] = co_await get_block_num(block_num_or_hash.tag(), /*latest_required=*/false);
        co_return co_await read_block_by_number(cache, block_num);
    }
    throw std::runtime_error{"invalid block_num_or_hash value"};
}

Task<std::optional<TransactionWithBlock>> BlockReader::read_transaction_by_hash(BlockCache& cache, const evmc::bytes32& transaction_hash) const {
    const auto result = co_await chain_storage_.read_block_num_by_transaction_hash(transaction_hash);
    if (!result) {
        co_return std::nullopt;
    }
    const auto block_with_hash = co_await read_block_by_number(cache, result->first);
    if (!block_with_hash) {
        co_return std::nullopt;
    }
    const auto& transactions = block_with_hash->block.transactions;
    for (size_t idx{0}; idx < transactions.size(); ++idx) {
        if (transaction_hash == transactions[idx].hash()) {
            const auto& block_header = block_with_hash->block.header;
            co_return TransactionWithBlock{
                block_with_hash,
                {transactions[idx], block_with_hash->hash, block_header.number, block_header.base_fee_per_gas, idx}};
        }
    }
    co_return std::nullopt;
}

Task<void> BlockReader::read_balance_changes(BlockCache& cache, const BlockNumOrHash& block_num_or_hash, BalanceChanges& balance_changes) const {
    const auto block_with_hash = co_await read_block_by_block_num_or_hash(cache, block_num_or_hash);
    if (!block_with_hash) {
        throw std::invalid_argument("read_balance_changes: block not found");
    }
    const auto block_num = block_with_hash->block.header.number;

    SILK_TRACE << "read_balance_changes: block_num: " << block_num;

    const auto start_txn_number = co_await transaction_.first_txn_num_in_block(block_num);
    const auto end_txn_number = co_await transaction_.first_txn_num_in_block(block_num + 1);

    const bool is_latest = co_await is_latest_block_num(block_num);
    std::optional<TxnId> txn_id;
    if (!is_latest) {
        txn_id = co_await transaction_.user_txn_id_at(block_num + 1);
    }
    StateReader state_reader{transaction_, txn_id};

    db::kv::api::HistoryRangeRequest query{
        .table = db::table::kAccountDomain,
        .from_timestamp = static_cast<db::kv::api::Timestamp>(start_txn_number),
        .to_timestamp = static_cast<db::kv::api::Timestamp>(end_txn_number),
        .ascending_order = true};

    auto paginated_result = co_await transaction_.history_range(std::move(query));
    auto it = co_await paginated_result.begin();

    while (const auto value = co_await it->next()) {
        intx::uint256 old_balance{0};
        intx::uint256 current_balance{0};

        if (!value->second.empty()) {
            const auto account{db::state::AccountCodec::from_encoded_storage_v3(value->second)};
            if (account) {
                old_balance = account->balance;
            }
        }

        evmc::address address = bytes_to_address(value->first);

        if (auto current_account = co_await state_reader.read_account(address)) {
            current_balance = current_account->balance;
        }

        if (current_balance != old_balance) {
            balance_changes[address] = current_balance;
        }
    }

    SILK_DEBUG << "Changed balances: " << balance_changes.size();
}

Task<BlockNum> BlockReader::get_forkchoice_block_num(const char* block_hash_tag) const {
    const auto kv_pair = co_await transaction_.get(table::kLastForkchoiceName, string_to_bytes(block_hash_tag));
    const auto block_hash_data = kv_pair.value;
    if (block_hash_data.empty()) {
        co_return 0;
    }
    const auto block_hash = to_bytes32(block_hash_data);
    auto block_num = co_await chain_storage_.read_block_num(block_hash);
    if (!block_num) {
        co_return 0;
    }
    co_return *block_num;
}

Task<bool> BlockReader::is_latest_block_num(BlockNum block_num) const {
    const auto last_executed_block_num = co_await get_latest_executed_block_num();
    co_return last_executed_block_num == block_num;
}

Task<BlockNum> BlockReader::get_block_num_by_tag(std::string_view block_id) const {
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

Task<std::pair<BlockNum, bool>> BlockReader::get_block_num(std::string_view block_id, bool latest_required) const {
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
        std::from_chars(block_id.data() + 2, block_id.data() + block_id.size(), block_num, 16);
        check_if_latest = latest_required;
    } else if (is_valid_dec(block_id)) {
        std::from_chars(block_id.data(), block_id.data() + block_id.size(), block_num, 10);
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

Task<BlockNum> BlockReader::get_block_num(std::string_view block_id) const {
    const auto [block_num, _] = co_await get_block_num(block_id, /*latest_required=*/false);
    co_return block_num;
}

Task<std::pair<BlockNum, bool>> BlockReader::get_block_num(const BlockNumOrHash& block_num_or_hash) const {
    if (block_num_or_hash.is_tag()) {
        co_return co_await get_block_num(block_num_or_hash.tag(), true);
    } else if (block_num_or_hash.is_number()) {
        co_return co_await get_block_num(silkworm::to_hex(block_num_or_hash.number(), true), true);
    } else if (block_num_or_hash.is_hash()) {
        const auto block_num = co_await chain_storage_.read_block_num(block_num_or_hash.hash());
        if (!block_num) {
            throw std::invalid_argument("Invalid Block Hash");
        }
        const auto latest_block_num = co_await get_latest_block_num();
        co_return std::make_pair(*block_num, *block_num == latest_block_num);
    } else {
        throw std::invalid_argument("Invalid Block Number or Hash");
    }
}

Task<BlockNum> BlockReader::get_block_num(const Hash& hash) const {
    auto bn = co_await chain_storage_.read_block_num(hash);
    ensure(bn != 0, "get_block_num: block with hash not found");
    co_return *bn;
}

Task<BlockNum> BlockReader::get_current_block_num() const {
    co_return co_await stages::get_sync_stage_progress(transaction_, stages::kFinish);
}

Task<BlockNum> BlockReader::get_max_block_num() const {
    co_return co_await stages::get_sync_stage_progress(transaction_, stages::kHeaders);
}

Task<BlockNum> BlockReader::get_latest_executed_block_num() const {
    co_return co_await stages::get_sync_stage_progress(transaction_, stages::kExecution);
}

Task<BlockNum> BlockReader::get_latest_block_num() const {
    const auto kv_pair = co_await transaction_.get(table::kLastForkchoiceName, string_to_bytes(kHeadBlockHash));
    const auto head_block_hash_data = kv_pair.value;
    if (!head_block_hash_data.empty()) {
        const auto head_block_hash = to_bytes32(head_block_hash_data);
        auto block_num = co_await chain_storage_.read_block_num(head_block_hash);
        if (!block_num) {
            co_return 0;
        }
        co_return *block_num;
    }
    co_return co_await get_latest_executed_block_num();
}

Task<BlockNum> BlockReader::get_forkchoice_finalized_block_num() const {
    co_return co_await get_forkchoice_block_num(kFinalizedBlockHash);
}

Task<BlockNum> BlockReader::get_forkchoice_safe_block_num() const {
    co_return co_await get_forkchoice_block_num(kSafeBlockHash);
}

Task<bool> BlockReader::is_latest_block_num(const BlockNumOrHash& block_num_or_hash) const {
    if (block_num_or_hash.is_tag()) {
        co_return block_num_or_hash.tag() == kLatestBlockId || block_num_or_hash.tag() == kPendingBlockId;
    } else {
        const auto latest_block_num = co_await get_latest_block_num();
        if (block_num_or_hash.is_number()) {
            co_return block_num_or_hash.number() == latest_block_num;
        } else {
            SILKWORM_ASSERT(block_num_or_hash.is_hash());
            const auto block_num = co_await chain_storage_.read_block_num(block_num_or_hash.hash());
            if (!block_num) {
                co_return false;
            }
            co_return *block_num == latest_block_num;
        }
    }
}

}  // namespace silkworm::rpc
