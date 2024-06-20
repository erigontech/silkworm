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

#include "remote_transaction.hpp"

#include <grpcpp/grpcpp.h>

#include <silkworm/db/tables.hpp>
#include <silkworm/rpc/state/remote_state.hpp>

namespace silkworm::rpc::ethdb::kv {

RemoteTransaction::RemoteTransaction(
    ::remote::KV::StubInterface& stub,
    agrpc::GrpcContext& grpc_context,
    StateCache* state_cache,
    BlockProvider block_provider,
    BlockNumberFromTxnHashProvider block_number_from_txn_hash_provider)
    : BaseTransaction(state_cache),
      block_provider_{std::move(block_provider)},
      block_number_from_txn_hash_provider_{std::move(block_number_from_txn_hash_provider)},
      tx_rpc_{stub, grpc_context} {}

Task<void> RemoteTransaction::open() {
    const auto tx_result = co_await tx_rpc_.request_and_read();
    tx_id_ = tx_result.tx_id();
    view_id_ = tx_result.view_id();
}

Task<std::shared_ptr<Cursor>> RemoteTransaction::cursor(const std::string& table) {
    co_return co_await get_cursor(table, false);
}

Task<std::shared_ptr<CursorDupSort>> RemoteTransaction::cursor_dup_sort(const std::string& table) {
    co_return co_await get_cursor(table, true);
}

Task<void> RemoteTransaction::close() {
    co_await tx_rpc_.writes_done_and_finish();
    cursors_.clear();
    tx_id_ = 0;
    view_id_ = 0;
}

Task<std::shared_ptr<CursorDupSort>> RemoteTransaction::get_cursor(const std::string& table, bool is_cursor_dup_sort) {
    if (is_cursor_dup_sort) {
        const auto cursor_it = dup_cursors_.find(table);
        if (cursor_it != dup_cursors_.end()) {
            co_return cursor_it->second;
        }
    } else {
        const auto cursor_it = cursors_.find(table);
        if (cursor_it != cursors_.end()) {
            co_return cursor_it->second;
        }
    }
    auto cursor = std::make_shared<RemoteCursor>(tx_rpc_);
    co_await cursor->open_cursor(table, is_cursor_dup_sort);
    if (is_cursor_dup_sort) {
        dup_cursors_[table] = cursor;
    } else {
        cursors_[table] = cursor;
    }
    co_return cursor;
}

std::shared_ptr<silkworm::State> RemoteTransaction::create_state(boost::asio::any_io_executor& executor, const ChainStorage& storage, BlockNum block_number) {
    return std::make_shared<silkworm::rpc::state::RemoteState>(executor, *this, storage, block_number);
}

std::shared_ptr<ChainStorage> RemoteTransaction::create_storage() {
    return std::make_shared<RemoteChainStorage>(*this, block_provider_, block_number_from_txn_hash_provider_);
}

}  // namespace silkworm::rpc::ethdb::kv
