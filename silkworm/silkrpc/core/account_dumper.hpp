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

#include <map>
#include <optional>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <evmc/evmc.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/cached_chain.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/ethdb/cursor.hpp>
#include <silkworm/silkrpc/ethdb/database.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>
#include <silkworm/silkrpc/types/block.hpp>
#include <silkworm/silkrpc/types/dump_account.hpp>

namespace silkworm::rpc::core {

class AccountDumper {
  public:
    explicit AccountDumper(ethdb::Transaction& transaction) : transaction_(transaction) {}

    AccountDumper(const AccountDumper&) = delete;
    AccountDumper& operator=(const AccountDumper&) = delete;

    Task<DumpAccounts> dump_accounts(
        BlockCache& cache,
        const BlockNumberOrHash& bnoh,
        ethbackend::BackEnd* backend,
        const evmc::address& start_address,
        int16_t max_result,
        bool exclude_code,
        bool exclude_storage);

  private:
    Task<void> load_accounts(ethdb::TransactionDatabase& tx_database, const std::vector<silkworm::KeyValue>& collected_data, DumpAccounts& dump_accounts, bool exclude_code);
    Task<void> load_storage(BlockNum block_number, DumpAccounts& dump_accounts);

    ethdb::Transaction& transaction_;
};

}  // namespace silkworm::rpc::core
