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

#include <evmc/evmc.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/db/chain/providers.hpp>
#include <silkworm/db/kv/api/transaction.hpp>

#include "version.hpp"

namespace silkworm::db::kv {

class StateReader {
  public:
    StateReader(kv::api::Transaction& tx, TxnId txn_id);

    StateReader(const StateReader&) = delete;
    StateReader& operator=(const StateReader&) = delete;

    Task<std::optional<Account>> read_account(const evmc::address& address) const;

    Task<evmc::bytes32> read_storage(const evmc::address& address,
                                     uint64_t incarnation,
                                     const evmc::bytes32& location_hash) const;

    Task<std::optional<Bytes>> read_code(const evmc::address& address, const evmc::bytes32& code_hash) const;

  private:
    kv::api::Transaction& tx_;
    TxnId txn_number_;
};

}  // namespace silkworm::db::kv
