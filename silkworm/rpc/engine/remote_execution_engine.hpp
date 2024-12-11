/*
   Copyright 2024 The Silkworm Authors

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

#include <agrpc/asio_grpc.hpp>

#include <silkworm/execution/grpc/client/remote_client.hpp>

#include "execution_engine.hpp"

namespace silkworm::rpc::engine {

class RemoteExecutionEngine final : public ExecutionEngine {
  public:
    RemoteExecutionEngine(const std::string& address_uri, agrpc::GrpcContext& grpc_context)
        : execution_client_{address_uri, grpc_context}, execution_service_{execution_client_.service()} {}
    ~RemoteExecutionEngine() override = default;

    Task<PayloadStatus> new_payload(const NewPayloadRequest& request, Msec timeout) override;
    Task<ForkChoiceUpdatedReply> fork_choice_updated(const ForkChoiceUpdatedRequest& request, Msec timeout) override;
    Task<ExecutionPayloadAndValue> get_payload(uint64_t payload_id, Msec timeout) override;
    Task<ExecutionPayloadBodies> get_payload_bodies_by_hash(const std::vector<Hash>& block_hashes, Msec timeout) override;
    Task<ExecutionPayloadBodies> get_payload_bodies_by_range(BlockNum start, uint64_t count, Msec timeout) override;

  private:
    execution::grpc::client::RemoteClient execution_client_;
    std::shared_ptr<execution::api::Service> execution_service_;
};

}  // namespace silkworm::rpc::engine
