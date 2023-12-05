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

#include "remote_database.hpp"

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/ethdb/kv/remote_transaction.hpp>

namespace silkworm::rpc::ethdb::kv {

RemoteDatabase::RemoteDatabase(agrpc::GrpcContext& grpc_context, const std::shared_ptr<grpc::Channel>& channel)
    : grpc_context_(grpc_context), stub_{remote::KV::NewStub(channel)} {
    SILK_TRACE << "RemoteDatabase::ctor " << this;
}

RemoteDatabase::RemoteDatabase(agrpc::GrpcContext& grpc_context, std::unique_ptr<remote::KV::StubInterface>&& stub)
    : grpc_context_(grpc_context), stub_(std::move(stub)) {
    SILK_TRACE << "RemoteDatabase::ctor " << this;
}

RemoteDatabase::~RemoteDatabase() {
    SILK_TRACE << "RemoteDatabase::dtor " << this;
}

Task<std::unique_ptr<Transaction>> RemoteDatabase::begin() {
    SILK_TRACE << "RemoteDatabase::begin " << this << " start";
    auto txn = std::make_unique<RemoteTransaction>(*stub_, grpc_context_);
    co_await txn->open();
    SILK_TRACE << "RemoteDatabase::begin " << this << " txn: " << txn.get() << " end";
    co_return txn;
}

}  // namespace silkworm::rpc::ethdb::kv
