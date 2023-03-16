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

#include <silkworm/node/concurrency/coroutine.hpp>

#include <agrpc/asio_grpc.hpp>
#include <boost/asio/awaitable.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/interfaces/execution/execution.grpc.pb.h>
#include <silkworm/node/backend/execution/execution_client.hpp>

namespace silkworm::execution {

class RemoteClient : public Client {
  public:
    RemoteClient(agrpc::GrpcContext& grpc_context, const std::shared_ptr<grpc::Channel>& channel);

    awaitable<void> start() override;

    awaitable<void> get_header(BlockNum block_number, Hash block_hash, BlockHeader& header) override;

    awaitable<void> get_body(BlockNum block_number, Hash block_hash, BlockBody& body) override;

    awaitable<void> insert_headers(const BlockVector& blocks) override;

    awaitable<void> insert_bodies(const BlockVector& blocks) override;

  private:
    agrpc::GrpcContext& grpc_context_;
    std::unique_ptr<::execution::Execution::Stub> stub_;
};

}  // namespace silkworm::execution
