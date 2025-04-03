// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#include <agrpc/asio_grpc.hpp>
#pragma GCC diagnostic pop

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
