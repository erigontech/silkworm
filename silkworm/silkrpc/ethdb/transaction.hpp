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

#include <memory>
#include <string>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/node/storage/chain_storage.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/ethdb/cursor.hpp>

namespace silkworm::rpc::ethdb {

using core::rawdb::DatabaseReader;

class Transaction {
  public:
    Transaction() = default;

    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;

    virtual ~Transaction() = default;

    [[nodiscard]] virtual uint64_t view_id() const = 0;

    virtual boost::asio::awaitable<void> open() = 0;

    virtual boost::asio::awaitable<std::shared_ptr<Cursor>> cursor(const std::string& table) = 0;

    virtual boost::asio::awaitable<std::shared_ptr<CursorDupSort>> cursor_dup_sort(const std::string& table) = 0;

    virtual std::shared_ptr<silkworm::State> create_state(boost::asio::any_io_executor& executor, const DatabaseReader& db_reader, uint64_t block_number) = 0;

    virtual std::shared_ptr<node::ChainStorage> get_storage(const DatabaseReader& reader) = 0;

    virtual boost::asio::awaitable<void> close() = 0;
};

}  // namespace silkworm::rpc::ethdb
