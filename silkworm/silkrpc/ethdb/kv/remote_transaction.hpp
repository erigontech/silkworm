/*
    Copyright 2020 The Silkrpc Authors

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

#include <map>
#include <memory>
#include <string>
#include <type_traits>

#include <silkworm/silkrpc/config.hpp>

#include <agrpc/grpc_context.hpp>
#include <boost/asio/awaitable.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/ethdb/cursor.hpp>
#include <silkworm/silkrpc/ethdb/kv/remote_cursor.hpp>
#include <silkworm/silkrpc/ethdb/kv/rpc.hpp>
#include <silkworm/silkrpc/ethdb/transaction.hpp>

namespace silkrpc::ethdb::kv {

class RemoteTransaction : public Transaction {
public:
    explicit RemoteTransaction(remote::KV::StubInterface& stub, agrpc::GrpcContext& grpc_context);

    ~RemoteTransaction();

    uint64_t tx_id() const override { return tx_id_; }

    boost::asio::awaitable<void> open() override;

    boost::asio::awaitable<std::shared_ptr<Cursor>> cursor(const std::string& table) override;

    boost::asio::awaitable<std::shared_ptr<CursorDupSort>> cursor_dup_sort(const std::string& table) override;

    boost::asio::awaitable<void> close() override;

private:
    boost::asio::awaitable<std::shared_ptr<CursorDupSort>> get_cursor(const std::string& table, bool is_cursor_dup_sort);

    std::map<std::string, std::shared_ptr<CursorDupSort>> cursors_;
    std::map<std::string, std::shared_ptr<CursorDupSort>> dup_cursors_;
    TxRpc tx_rpc_;
    uint64_t tx_id_;
};

} // namespace silkrpc::ethdb::kv

