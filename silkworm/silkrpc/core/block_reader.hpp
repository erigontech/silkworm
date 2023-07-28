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

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>
#include <silkworm/silkrpc/types/block.hpp>

namespace silkworm::rpc {

using boost::asio::awaitable;

using BalanceChanges = std::map<evmc::address, intx::uint256>;

void to_json(nlohmann::json& json, const BalanceChanges& bc);

class BlockReader {
  public:
    explicit BlockReader(ethdb::Transaction& transaction) : transaction_(transaction) {}

    BlockReader(const BlockReader&) = delete;
    BlockReader& operator=(const BlockReader&) = delete;

    [[nodiscard]] awaitable<void> read_balance_changes(BlockCache& cache, const BlockNumberOrHash& bnoh, BalanceChanges& balance_changes) const;

  private:
    ethdb::Transaction& transaction_;
};

}  // namespace silkworm::rpc
