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

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/db/kv/txn_num.hpp>

#include "version.hpp"

namespace silkworm::db::state {

class StateReader {
  public:
    StateReader(kv::api::Transaction& tx, BlockNum block_number);

    StateReader(const StateReader&) = delete;
    StateReader& operator=(const StateReader&) = delete;

    Task<std::optional<Account>> read_account(const evmc::address& address) const;

    Task<evmc::bytes32> read_storage(const evmc::address& address,
                                     uint64_t incarnation,
                                     const evmc::bytes32& location_hash) const;

    Task<std::optional<Bytes>> read_code(const evmc::address& address, const evmc::bytes32& code_hash) const;

  private:
    Task<std::optional<Account>> read_account_v2(const evmc::address& address) const;
    Task<std::optional<Account>> read_account_v3(const evmc::address& address) const;

    Task<evmc::bytes32> read_storage_v2(const evmc::address& address,
                                        uint64_t incarnation,
                                        const evmc::bytes32& location_hash) const;
    Task<evmc::bytes32> read_storage_v3(const evmc::address& address,
                                        uint64_t incarnation,
                                        const evmc::bytes32& location_hash) const;

    Task<std::optional<Bytes>> read_code_v2(const evmc::address& address, const evmc::bytes32& code_hash) const;
    Task<std::optional<Bytes>> read_code_v3(const evmc::address& address, const evmc::bytes32& code_hash) const;

    Task<std::optional<Bytes>> read_historical_account_v2(const evmc::address& address) const;
    Task<std::optional<Bytes>> read_historical_storage_v2(const evmc::address& address,
                                                          uint64_t incarnation,
                                                          const evmc::bytes32& location_hash) const;

    Task<txn::TxNum> first_txn_num_in_block() const;

    kv::api::Transaction& tx_;
    BlockNum block_number_;
    mutable std::optional<txn::TxNum> txn_number_;

    using ReadAccountImpl = Task<std::optional<Account>> (StateReader::*)(const evmc::address&) const;
    ReadAccountImpl read_account_impl_v2_{&StateReader::read_account_v2};
    ReadAccountImpl read_account_impl_v3_{&StateReader::read_account_v3};
    ReadAccountImpl read_account_impl_{read_account_impl_v2_};

    using ReadStorageImpl = Task<evmc::bytes32> (StateReader::*)(const evmc::address&, uint64_t, const evmc::bytes32&) const;
    ReadStorageImpl read_storage_impl_v2_{&StateReader::read_storage_v2};
    ReadStorageImpl read_storage_impl_v3_{&StateReader::read_storage_v3};
    ReadStorageImpl read_storage_impl_{read_storage_impl_v2_};

    using ReadCodeImpl = Task<std::optional<Bytes>> (StateReader::*)(const evmc::address&, const evmc::bytes32&) const;
    ReadCodeImpl read_code_impl_v2_{&StateReader::read_code_v2};
    ReadCodeImpl read_code_impl_v3_{&StateReader::read_code_v3};
    ReadCodeImpl read_code_impl_{read_code_impl_v2_};
};

}  // namespace silkworm::db::state
