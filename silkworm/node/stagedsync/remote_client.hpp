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
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <agrpc/asio_grpc.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/interfaces/execution/execution.grpc.pb.h>
#include <silkworm/node/stagedsync/client.hpp>

namespace silkworm::execution {

namespace asio = boost::asio;

//! The settings required to run a RemoteClient. Default values are for co-located out-of-process execution.
struct RemoteSettings {
    std::string target{"localhost:9090"};
};

//! A client of 'execution' gRPC interface running out-of-process or remotely from server.
class RemoteClient : public Client {
  public:
    explicit RemoteClient(rpc::ClientContext& context, const RemoteSettings& settings = {});

    asio::io_context& get_executor() override;

    // actions
    Task<void> insert_headers(const BlockVector& blocks) override;
    Task<void> insert_bodies(const BlockVector& blocks) override;
    Task<void> insert_blocks(const BlockVector& blocks) override;

    Task<ValidationResult> validate_chain(Hash head_block_hash) override;

    Task<ForkChoiceApplication> update_fork_choice(Hash head_block_hash, std::optional<Hash> finalized_block_hash) override;

    // state
    Task<BlockNum> block_progress() override;
    Task<BlockId> last_fork_choice() override;

    // header/body retrieval
    Task<std::optional<BlockHeader>> get_header(Hash block_hash) override;
    Task<std::optional<BlockHeader>> get_header(BlockNum height, Hash hash) override;
    Task<std::optional<BlockBody>> get_body(Hash block_hash) override;
    Task<std::optional<BlockBody>> get_body(BlockNum block_number) override;

    Task<bool> is_canonical(Hash block_hash) override;
    Task<std::optional<BlockNum>> get_block_num(Hash block_hash) override;

    Task<std::vector<BlockHeader>> get_last_headers(BlockNum limit) override;
    Task<std::optional<TotalDifficulty>> get_header_td(Hash, std::optional<BlockNum>) override;

  private:
    rpc::ClientContext& context_;
    std::shared_ptr<::grpc::Channel> channel_;
    std::unique_ptr<::execution::Execution::StubInterface> stub_;
};

}  // namespace silkworm::execution
