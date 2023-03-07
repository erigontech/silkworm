/*
    Copyright 2022 The Silkrpc Authors

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

#include "local_transaction.hpp"

#include <utility>

#include "silkworm/node/db/mdbx.hpp"

#include <silkworm/silkrpc/config.hpp>
#include <silkworm/silkrpc/common/log.hpp>

namespace silkrpc::ethdb::file {

boost::asio::awaitable<void> LocalTransaction::open() {
    // Create a new read-only transaction.
    read_only_txn_ = chaindata_env_->start_read();
    co_return;
}

boost::asio::awaitable<std::shared_ptr<Cursor>> LocalTransaction::cursor(const std::string& table) {
    co_return co_await get_cursor(table, false);
}

boost::asio::awaitable<std::shared_ptr<CursorDupSort>> LocalTransaction::cursor_dup_sort(const std::string& table) {
    co_return co_await get_cursor(table, true);
}

boost::asio::awaitable<void> LocalTransaction::close() {
    cursors_.clear();
    tx_id_ = 0;
    co_return;
}

boost::asio::awaitable<std::shared_ptr<CursorDupSort>> LocalTransaction::get_cursor(const std::string& table, bool is_cursor_sorted) {
    if (is_cursor_sorted) {
       auto cursor_it = dup_cursors_.find(table);
       if (cursor_it != dup_cursors_.end()) {
           co_return cursor_it->second;
       }
    } else {
       auto cursor_it = cursors_.find(table);
       if (cursor_it != cursors_.end()) {
           co_return cursor_it->second;
       }
    }
    auto cursor = std::make_shared<LocalCursor>(read_only_txn_, ++last_cursor_id_, table);
    co_await cursor->open_cursor(table, is_cursor_sorted);
    if (is_cursor_sorted) {
       dup_cursors_[table] = cursor;
    } else {
       cursors_[table] = cursor;
    }
    co_return cursor;
}

} // namespace silkrpc::ethdb::file
