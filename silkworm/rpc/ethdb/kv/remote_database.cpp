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

#include <silkworm/db/chain/remote_chain_storage.hpp>
#include <silkworm/db/kv/grpc/client/remote_transaction.hpp>
#include <silkworm/infra/common/log.hpp>

#include "backend_providers.hpp"

namespace silkworm::rpc::ethdb::kv {

using db::kv::grpc::client::RemoteTransaction;

RemoteDatabase::RemoteDatabase(ethbackend::BackEnd* backend,
                               StateCache* state_cache,
                               agrpc::GrpcContext& grpc_context,
                               const std::shared_ptr<grpc::Channel>& channel)
    : backend_{backend}, state_cache_{state_cache}, grpc_context_{grpc_context}, stub_{remote::KV::NewStub(channel)} {
    SILK_TRACE << "RemoteDatabase::ctor " << this;
}

RemoteDatabase::RemoteDatabase(ethbackend::BackEnd* backend,
                               StateCache* state_cache,
                               agrpc::GrpcContext& grpc_context,
                               std::unique_ptr<remote::KV::StubInterface>&& stub)
    : backend_{backend}, state_cache_{state_cache}, grpc_context_{grpc_context}, stub_(std::move(stub)) {
    SILK_TRACE << "RemoteDatabase::ctor " << this;
}

RemoteDatabase::~RemoteDatabase() {
    SILK_TRACE << "RemoteDatabase::dtor " << this;
}

Task<std::unique_ptr<db::kv::api::Transaction>> RemoteDatabase::begin() {
    SILK_TRACE << "RemoteDatabase::begin " << this << " start";
    auto txn = std::make_unique<RemoteTransaction>(*stub_,
                                                   grpc_context_,
                                                   state_cache_,
                                                   ethdb::kv::make_backend_providers(backend_));
    co_await txn->open();
    SILK_TRACE << "RemoteDatabase::begin " << this << " txn: " << txn.get() << " end";
    co_return txn;
}

}  // namespace silkworm::rpc::ethdb::kv
