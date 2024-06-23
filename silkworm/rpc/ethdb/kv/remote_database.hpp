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
#include <utility>

#include <agrpc/grpc_context.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>
#include <silkworm/rpc/ethbackend/remote_backend.hpp>
#include <silkworm/rpc/ethdb/database.hpp>

namespace silkworm::rpc::ethdb::kv {

using db::kv::api::StateCache;

class RemoteDatabase : public Database {
  public:
    RemoteDatabase(ethbackend::BackEnd* backend,
                   StateCache* state_cache,
                   agrpc::GrpcContext& grpc_context,
                   const std::shared_ptr<grpc::Channel>& channel);
    RemoteDatabase(ethbackend::BackEnd* backend,
                   StateCache* state_cache,
                   agrpc::GrpcContext& grpc_context,
                   std::unique_ptr<remote::KV::StubInterface>&& stub);
    ~RemoteDatabase() override;

    RemoteDatabase(const RemoteDatabase&) = delete;
    RemoteDatabase& operator=(const RemoteDatabase&) = delete;

    Task<std::unique_ptr<db::kv::api::Transaction>> begin() override;

  private:
    ethbackend::BackEnd* backend_;
    StateCache* state_cache_;
    agrpc::GrpcContext& grpc_context_;
    std::unique_ptr<::remote::KV::StubInterface> stub_;
};

}  // namespace silkworm::rpc::ethdb::kv
