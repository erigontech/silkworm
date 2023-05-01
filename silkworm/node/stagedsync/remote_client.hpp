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

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <agrpc/asio_grpc.hpp>
#include <boost/asio/awaitable.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/interfaces/execution/execution.grpc.pb.h>
#include <silkworm/node/stagedsync/client.hpp>

namespace silkworm::execution {

class RemoteClient : public Client {
  public:
    RemoteClient(agrpc::GrpcContext& grpc_context, const std::shared_ptr<grpc::Channel>& channel);

    auto get_header(BlockNum block_number, Hash block_hash) -> awaitable<std::optional<BlockHeader>> override;

    auto get_body(BlockNum block_number, Hash block_hash) -> awaitable<BlockBody> override;

    auto is_canonical(Hash block_hash) -> awaitable<bool> override;

    auto get_block_num(Hash block_hash) -> awaitable<BlockNum> override;

    auto insert_headers(const BlockVector& blocks) -> awaitable<void> override;

    auto insert_bodies(const BlockVector& blocks) -> awaitable<void> override;

    auto validate_chain(Hash head_block_hash) -> awaitable<ValidationResult> override;

    auto update_fork_choice(Hash head_block_hash, std::optional<Hash> finalized_block_hash = std::nullopt) -> awaitable<ForkChoiceApplication> override;

  private:
    agrpc::GrpcContext& grpc_context_;
    std::unique_ptr<::execution::Execution::Stub> stub_;
};

}  // namespace silkworm::execution
