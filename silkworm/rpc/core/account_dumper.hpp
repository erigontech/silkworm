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

#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/core/cached_chain.hpp>
#include <silkworm/rpc/types/block.hpp>
#include <silkworm/rpc/types/dump_account.hpp>

namespace silkworm::rpc::core {

using db::kv::api::KeyValue;

class AccountDumper {
  public:
    AccountDumper(db::kv::api::Transaction& transaction, db::kv::api::StateCache* state_cache)
        : transaction_(transaction), state_cache_(state_cache) {}

    AccountDumper(const AccountDumper&) = delete;
    AccountDumper& operator=(const AccountDumper&) = delete;

    Task<DumpAccounts> dump_accounts(
        BlockCache& cache,
        const BlockNumOrHash& block_num_or_hash,
        const evmc::address& start_address,
        int16_t max_result,
        bool exclude_code,
        bool exclude_storage);

  private:
    Task<void> load_storage(BlockNum block_num, DumpAccounts& dump_accounts);

    db::kv::api::Transaction& transaction_;
    db::kv::api::StateCache* state_cache_;
};

}  // namespace silkworm::rpc::core
