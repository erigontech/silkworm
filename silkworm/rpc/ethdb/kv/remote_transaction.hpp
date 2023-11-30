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

#include <map>
#include <memory>
#include <string>
#include <type_traits>

#include <silkworm/infra/concurrency/task.hpp>

#include <agrpc/grpc_context.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/rpc/ethdb/cursor.hpp>
#include <silkworm/rpc/ethdb/kv/cached_database.hpp>
#include <silkworm/rpc/ethdb/kv/remote_cursor.hpp>
#include <silkworm/rpc/ethdb/kv/rpc.hpp>
#include <silkworm/rpc/ethdb/transaction.hpp>

namespace silkworm::rpc::ethdb::kv {

class RemoteTransaction : public Transaction {
  public:
    RemoteTransaction(::remote::KV::StubInterface& stub, agrpc::GrpcContext& grpc_context)
        : tx_rpc_{stub, grpc_context} {}

    ~RemoteTransaction() override = default;

    uint64_t view_id() const override { return view_id_; }

    Task<void> open() override;

    Task<std::shared_ptr<Cursor>> cursor(const std::string& table) override;

    Task<std::shared_ptr<CursorDupSort>> cursor_dup_sort(const std::string& table) override;

    std::shared_ptr<silkworm::State> create_state(boost::asio::any_io_executor& executor, const DatabaseReader& db_reader, const ChainStorage& storage, BlockNum block_number) override;

    std::shared_ptr<ChainStorage> create_storage(const DatabaseReader& db_reader, ethbackend::BackEnd* backend) override;

    Task<void> close() override;

  private:
    Task<std::shared_ptr<CursorDupSort>> get_cursor(const std::string& table, bool is_cursor_dup_sort);

    std::map<std::string, std::shared_ptr<CursorDupSort>> cursors_;
    std::map<std::string, std::shared_ptr<CursorDupSort>> dup_cursors_;
    TxRpc tx_rpc_;
    uint64_t view_id_{0};
};

}  // namespace silkworm::rpc::ethdb::kv
