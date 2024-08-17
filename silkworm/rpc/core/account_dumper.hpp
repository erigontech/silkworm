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
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/cached_chain.hpp>
#include <silkworm/rpc/ethdb/database.hpp>
#include <silkworm/rpc/types/block.hpp>
#include <silkworm/rpc/types/dump_account.hpp>

namespace silkworm::rpc::core {

using db::kv::api::KeyValue;

class AccountDumper {
  public:
    explicit AccountDumper(db::kv::api::Transaction& transaction) : transaction_(transaction) {}

    AccountDumper(const AccountDumper&) = delete;
    AccountDumper& operator=(const AccountDumper&) = delete;

    Task<void> dump_accounts(
        BlockCache& cache,
        const BlockNumberOrHash& bnoh,
        const evmc::address& start_address,
        int16_t max_result,
        bool exclude_code,
        bool exclude_storage,
        DumpAccounts& dump_accounts);

  private:
    Task<void> load_accounts(const std::vector<KeyValue>& collected_data, DumpAccounts& dump_accounts, bool exclude_code);
    Task<void> load_storage(BlockNum block_number, DumpAccounts& dump_accounts);

    db::kv::api::Transaction& transaction_;
};

}  // namespace silkworm::rpc::core
