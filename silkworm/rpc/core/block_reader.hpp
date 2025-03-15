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

inline constexpr const char* kEarliestBlockId{"earliest"};
inline constexpr const char* kLatestBlockId{"latest"};
inline constexpr const char* kPendingBlockId{"pending"};
inline constexpr const char* kFinalizedBlockId{"finalized"};
inline constexpr const char* kSafeBlockId{"safe"};
inline constexpr const char* kLatestExecutedBlockId{"latestExecuted"};

class BlockReader {
  public:
    explicit BlockReader(const db::chain::ChainStorage& chain_storage,
                         db::kv::api::Transaction& transaction,
                         db::kv::api::StateCache* state_cache)
        : chain_storage_(chain_storage), transaction_(transaction), state_cache_(state_cache) {}

    BlockReader(const BlockReader&) = delete;
    BlockReader& operator=(const BlockReader&) = delete;

    Task<void> read_balance_changes(BlockCache& cache, const BlockNumOrHash& block_num_or_hash, BalanceChanges& balance_changes) const;

    Task<bool> is_latest_block_num(BlockNum block_num) const;

    Task<BlockNum> get_block_num_by_tag(const std::string& block_id) const;

    Task<std::pair<BlockNum, bool>> get_block_num(const std::string& block_id, bool latest_required) const;

    Task<BlockNum> get_block_num(const std::string& block_id) const;

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

  private:
    Task<BlockNum> get_forkchoice_block_num(const char* block_hash_tag) const;
    const db::chain::ChainStorage& chain_storage_;
    db::kv::api::Transaction& transaction_;
    db::kv::api::StateCache* state_cache_;
};

}  // namespace silkworm::rpc
