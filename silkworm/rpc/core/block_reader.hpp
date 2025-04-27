// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/db/chain/chain_storage.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/types/block.hpp>

namespace silkworm::rpc {

using BalanceChanges = std::map<evmc::address, intx::uint256>;

void to_json(nlohmann::json& json, const BalanceChanges& balance_changes);

inline constexpr std::string_view kEarliestBlockId{"earliest"};
inline constexpr std::string_view kLatestBlockId{"latest"};
inline constexpr std::string_view kPendingBlockId{"pending"};
inline constexpr std::string_view kFinalizedBlockId{"finalized"};
inline constexpr std::string_view kSafeBlockId{"safe"};
inline constexpr std::string_view kLatestExecutedBlockId{"latestExecuted"};

class BlockReader {
  public:
    BlockReader(const db::chain::ChainStorage& chain_storage,
                db::kv::api::Transaction& transaction)
        : chain_storage_(chain_storage), transaction_(transaction) {}

    BlockReader(const BlockReader&) = delete;
    BlockReader& operator=(const BlockReader&) = delete;

    Task<std::shared_ptr<BlockWithHash>> read_block_by_number(BlockCache& cache, BlockNum block_num) const;

    Task<std::shared_ptr<BlockWithHash>> read_block_by_hash(BlockCache& cache, const evmc::bytes32& block_hash) const;

    Task<std::shared_ptr<BlockWithHash>> read_block_by_block_num_or_hash(BlockCache& cache, const BlockNumOrHash& block_num_or_hash) const;

    Task<std::optional<TransactionWithBlock>> read_transaction_by_hash(BlockCache& cache, const evmc::bytes32& transaction_hash) const;

    Task<void> read_balance_changes(const BlockNumOrHash& block_num_or_hash, BalanceChanges& balance_changes) const;

    Task<bool> is_latest_block_num(BlockNum block_num) const;

    Task<BlockNum> get_block_num_by_tag(std::string_view block_id) const;

    Task<std::pair<BlockNum, bool>> get_block_num(std::string_view block_id, bool latest_required) const;

    Task<BlockNum> get_block_num(std::string_view block_id) const;

    Task<std::pair<BlockNum, bool>> get_block_num(const BlockNumOrHash& block_num_or_hash) const;

    Task<BlockNum> get_block_num(const Hash& hash) const;

    Task<BlockNum> get_current_block_num() const;

    Task<BlockNum> get_max_block_num() const;

    Task<BlockNum> get_latest_block_num() const;

    Task<BlockNum> get_latest_executed_block_num() const;

    Task<BlockNum> get_forkchoice_finalized_block_num() const;

    Task<BlockNum> get_forkchoice_safe_block_num() const;

    Task<bool> is_latest_block_num(const BlockNumOrHash& block_num_or_hash) const;

    Task<std::optional<BlockHeader>> read_header(BlockNum block_num) { co_return co_await chain_storage_.read_canonical_header(block_num); }

    Task<std::optional<BlockHeader>> read_header_by_block_num_or_hash(const BlockNumOrHash& block_num_or_hash) const;

  private:
    Task<BlockNum> get_forkchoice_block_num(std::string_view block_hash_tag) const;
    const db::chain::ChainStorage& chain_storage_;
    db::kv::api::Transaction& transaction_;
};

}  // namespace silkworm::rpc
