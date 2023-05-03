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

namespace asio = boost::asio;

class RemoteClient : public Client {
  public:
    RemoteClient(agrpc::GrpcContext& grpc_context, const std::shared_ptr<grpc::Channel>& channel);

    // actions
    ERIGON_API auto insert_headers(const BlockVector& blocks) -> asio::awaitable<void> override;
    ERIGON_API auto insert_bodies(const BlockVector& blocks) -> asio::awaitable<void> override;
    auto insert_blocks(const BlockVector& blocks) -> asio::awaitable<void> override;

    ERIGON_API auto validate_chain(Hash head_block_hash) -> asio::awaitable<ValidationResult> override;

    ERIGON_API auto update_fork_choice(Hash head_block_hash,
                                       std::optional<Hash> finalized_block_hash = std::nullopt) -> asio::awaitable<ForkChoiceApplication> override;

    // state
    auto block_progress() -> asio::awaitable<BlockNum> override;
    auto last_fork_choice() -> asio::awaitable<BlockId> override;

    // header/body retrieval
    ERIGON_API auto get_header(Hash block_hash) -> asio::awaitable<std::optional<BlockHeader>> override;
    ERIGON_API auto get_body(Hash block_hash) -> asio::awaitable<BlockBody> override;

    ERIGON_API auto is_canonical(Hash block_hash) -> asio::awaitable<bool> override;
    ERIGON_API auto get_block_num(Hash block_hash) -> asio::awaitable<BlockNum> override;

    auto get_last_headers(BlockNum limit) -> asio::awaitable<std::vector<BlockHeader>> override;

  private:
    agrpc::GrpcContext& grpc_context_;
    std::unique_ptr<::execution::Execution::Stub> stub_;
};

}  // namespace silkworm::execution
