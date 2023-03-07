/*
   Copyright 2021 The Silkrpc Authors

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
#include <map>

#include <nlohmann/json.hpp>
#include <silkworm/silkrpc/config.hpp>

#include <boost/asio/awaitable.hpp>
#include <evmc/evmc.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>

#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/ethdb/cursor.hpp>
#include <silkworm/silkrpc/ethdb/database.hpp>
#include <silkworm/silkrpc/types/block.hpp>

namespace silkrpc {

class AccountWalker {
public:
    using Collector = std::function<bool(silkworm::ByteView, silkworm::ByteView)>;

    explicit AccountWalker(silkrpc::ethdb::Transaction& transaction) : transaction_(transaction) {}

    AccountWalker(const AccountWalker&) = delete;
    AccountWalker& operator=(const AccountWalker&) = delete;

    boost::asio::awaitable<void> walk_of_accounts(uint64_t block_number, const evmc::address& start_address, Collector& collector);

private:
    boost::asio::awaitable<KeyValue> next(silkrpc::ethdb::Cursor& cursor, uint64_t len);
    boost::asio::awaitable<KeyValue> seek(silkrpc::ethdb::Cursor& cursor, const silkworm::ByteView key, uint64_t len);
    boost::asio::awaitable<silkrpc::ethdb::SplittedKeyValue> next(silkrpc::ethdb::SplitCursor& cursor, uint64_t number, uint64_t block, silkworm::Bytes addr);
    boost::asio::awaitable<silkrpc::ethdb::SplittedKeyValue> seek(silkrpc::ethdb::SplitCursor& cursor, uint64_t number);

    silkrpc::ethdb::Transaction& transaction_;
};

} // namespace silkrpc

