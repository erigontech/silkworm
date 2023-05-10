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
#include <utility>
#include <vector>

#include <agrpc/grpc_context.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <evmc/evmc.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/interfaces/remote/ethbackend.grpc.pb.h>
#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/silkrpc/ethbackend/backend.hpp>
#include <silkworm/silkrpc/types/execution_payload.hpp>

namespace silkworm::rpc::ethbackend {

using boost::asio::awaitable;

class RemoteBackEnd final : public BackEnd {
  public:
    explicit RemoteBackEnd(boost::asio::io_context& context, const std::shared_ptr<grpc::Channel>& channel,
                           agrpc::GrpcContext& grpc_context);
    explicit RemoteBackEnd(boost::asio::io_context::executor_type executor,
                           std::unique_ptr<::remote::ETHBACKEND::StubInterface> stub,
                           agrpc::GrpcContext& grpc_context);
    ~RemoteBackEnd() override;

    awaitable<evmc::address> etherbase() override;
    awaitable<uint64_t> protocol_version() override;
    awaitable<uint64_t> net_version() override;
    awaitable<std::string> client_version() override;
    awaitable<uint64_t> net_peer_count() override;
    awaitable<ExecutionPayload> engine_get_payload_v1(uint64_t payload_id) override;
    awaitable<PayloadStatus> engine_new_payload_v1(const ExecutionPayload& payload) override;
    awaitable<ForkChoiceUpdatedReply> engine_forkchoice_updated_v1(const ForkChoiceUpdatedRequest& fcu_request) override;
    awaitable<NodeInfos> engine_node_info() override;
    awaitable<PeerInfos> peers() override;

  private:
    static ExecutionPayload decode_execution_payload(const ::types::ExecutionPayload& execution_payload_grpc);
    static ::types::ExecutionPayload encode_execution_payload(const ExecutionPayload& execution_payload);
    static ::remote::EngineForkChoiceState* encode_forkchoice_state(const ForkChoiceState& forkchoice_state);
    static ::remote::EnginePayloadAttributes* encode_payload_attributes(const PayloadAttributes& payload_attributes);
    static ::remote::EngineForkChoiceUpdatedRequest encode_forkchoice_updated_request(const ForkChoiceUpdatedRequest& fcu_request);
    static PayloadStatus decode_payload_status(const ::remote::EnginePayloadStatus& payload_status_grpc);
    static std::string decode_status_message(const ::remote::EngineStatus& status);

    boost::asio::io_context::executor_type executor_;
    std::unique_ptr<::remote::ETHBACKEND::StubInterface> stub_;
    agrpc::GrpcContext& grpc_context_;
};

}  // namespace silkworm::rpc::ethbackend
