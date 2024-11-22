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

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/db/kv/api/endpoint/key_value.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/ethdb/split_cursor.hpp>

namespace silkworm::rpc {

using db::kv::api::KeyValue;

class AccountWalker {
  public:
    using Collector = std::function<bool(ByteView, ByteView)>;

    explicit AccountWalker(db::kv::api::Transaction& transaction) : transaction_(transaction) {}

    AccountWalker(const AccountWalker&) = delete;
    AccountWalker& operator=(const AccountWalker&) = delete;

    Task<void> walk_of_accounts(BlockNum block_number, const evmc::address& start_address, Collector& collector);

  private:
    Task<KeyValue> next(db::kv::api::Cursor& cursor, uint64_t len);
    Task<KeyValue> seek(db::kv::api::Cursor& cursor, ByteView key, uint64_t len);
    Task<ethdb::SplittedKeyValue> next(ethdb::SplitCursor& cursor, BlockNum number, BlockNum block, Bytes addr);
    Task<ethdb::SplittedKeyValue> seek(ethdb::SplitCursor& cursor, BlockNum number);

    db::kv::api::Transaction& transaction_;
};

}  // namespace silkworm::rpc
