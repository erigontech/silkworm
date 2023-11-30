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

#include "local_transaction.hpp"

#include <silkworm/rpc/core/local_state.hpp>
#include <silkworm/rpc/storage/local_chain_storage.hpp>

namespace silkworm::rpc::ethdb::file {

Task<void> LocalTransaction::open() {
    co_return;
}

Task<std::shared_ptr<Cursor>> LocalTransaction::cursor(const std::string& table) {
    co_return co_await get_cursor(table, false);
}

Task<std::shared_ptr<CursorDupSort>> LocalTransaction::cursor_dup_sort(const std::string& table) {
    co_return co_await get_cursor(table, true);
}

Task<void> LocalTransaction::close() {
    cursors_.clear();
    co_return;
}

Task<std::shared_ptr<CursorDupSort>> LocalTransaction::get_cursor(const std::string& table, bool is_cursor_sorted) {
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
    auto cursor = std::make_shared<LocalCursor>(txn_, ++last_cursor_id_, table);
    co_await cursor->open_cursor(table, is_cursor_sorted);
    if (is_cursor_sorted) {
        dup_cursors_[table] = cursor;
    } else {
        cursors_[table] = cursor;
    }
    co_return cursor;
}

std::shared_ptr<silkworm::State> LocalTransaction::create_state(boost::asio::any_io_executor&, const core::rawdb::DatabaseReader&, const ChainStorage&, BlockNum block_number) {
    return std::make_shared<silkworm::rpc::state::LocalState>(block_number, chaindata_env_);
}

std::shared_ptr<ChainStorage> LocalTransaction::create_storage(const DatabaseReader&, ethbackend::BackEnd*) {
    return std::make_shared<LocalChainStorage>(txn_);
}

}  // namespace silkworm::rpc::ethdb::file
