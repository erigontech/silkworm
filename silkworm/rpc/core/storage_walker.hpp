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
#include <nlohmann/json.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/ethdb/database.hpp>
#include <silkworm/rpc/types/block.hpp>

namespace silkworm::rpc {

silkworm::Bytes make_key(const evmc::address& address, const evmc::bytes32& location);

class StorageWalker {
  public:
    using AccountCollector = std::function<bool(const evmc::address&, silkworm::ByteView, silkworm::ByteView)>;
    using StorageCollector = std::function<bool(const silkworm::ByteView, silkworm::ByteView, silkworm::ByteView)>;

    explicit StorageWalker(db::kv::api::Transaction& transaction) : transaction_(transaction) {}

    StorageWalker(const StorageWalker&) = delete;
    StorageWalker& operator=(const StorageWalker&) = delete;

    Task<void> walk_of_storages(
        BlockNum block_number,
        const evmc::address& address,
        const evmc::bytes32& start_location,
        uint64_t incarnation,
        AccountCollector& collector);

    Task<void> storage_range_at(
        TxnId txn_number,
        const evmc::address& address,
        const evmc::bytes32& start_location,
        StorageCollector& collector);

  private:
    int compare_empty_greater(const ByteView& key1, const ByteView& key2);

    db::kv::api::Transaction& transaction_;
};

}  // namespace silkworm::rpc
