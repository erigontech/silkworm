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

#include <optional>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/compose.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/this_coro.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/db/chain/chain_storage.hpp>
#include <silkworm/db/remote/kv/api/endpoint/transaction.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/types/block.hpp>

namespace silkworm::rpc {

using BalanceChanges = std::map<evmc::address, intx::uint256>;

void to_json(nlohmann::json& json, const BalanceChanges& balance_changes);

class BlockReader {
  public:
    explicit BlockReader(const db::chain::ChainStorage& chain_storage, db::kv::api::Transaction& transaction)
        : chain_storage_(chain_storage), transaction_(transaction) {}

    BlockReader(const BlockReader&) = delete;
    BlockReader& operator=(const BlockReader&) = delete;

    [[nodiscard]] Task<void> read_balance_changes(BlockCache& cache, const BlockNumberOrHash& bnoh, BalanceChanges& balance_changes) const;

  private:
    [[nodiscard]] Task<void> load_addresses(BlockNum block_number, BalanceChanges& balance_changes) const;

    const db::chain::ChainStorage& chain_storage_;
    db::kv::api::Transaction& transaction_;
};

}  // namespace silkworm::rpc
