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

#include "remote_transaction.hpp"

#include <utility>

#include <silkworm/silkrpc/config.hpp>

#include <grpcpp/grpcpp.h>

#include <silkworm/silkrpc/common/log.hpp>

namespace silkrpc::ethdb::kv {

RemoteTransaction::RemoteTransaction(remote::KV::StubInterface& stub, agrpc::GrpcContext& grpc_context)
    : tx_rpc_{stub, grpc_context} {
}

RemoteTransaction::~RemoteTransaction() {
}

boost::asio::awaitable<void> RemoteTransaction::open() {
    tx_id_ = (co_await tx_rpc_.request_and_read()).txid();
}

boost::asio::awaitable<std::shared_ptr<Cursor>> RemoteTransaction::cursor(const std::string& table) {
    co_return co_await get_cursor(table, false);
}

boost::asio::awaitable<std::shared_ptr<CursorDupSort>> RemoteTransaction::cursor_dup_sort(const std::string& table) {
    co_return co_await get_cursor(table, true);
}

boost::asio::awaitable<void> RemoteTransaction::close() {
    co_await tx_rpc_.writes_done_and_finish();
    cursors_.clear();
    tx_id_ = 0;
}

boost::asio::awaitable<std::shared_ptr<CursorDupSort>> RemoteTransaction::get_cursor(const std::string& table, bool is_cursor_sorted) {
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
    auto cursor = std::make_shared<RemoteCursor>(tx_rpc_);
    co_await cursor->open_cursor(table, is_cursor_sorted);
    if (is_cursor_sorted) {
       dup_cursors_[table] = cursor;
    } else {
       cursors_[table] = cursor;
    }
    co_return cursor;
}

} // namespace silkrpc::ethdb::kv
