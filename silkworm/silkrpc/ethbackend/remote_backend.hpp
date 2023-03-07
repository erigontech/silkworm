/*
    Copyright 2022 The Silkrpc Authors

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
#include <silkworm/silkrpc/types/execution_payload.hpp>
#include <silkworm/silkrpc/ethbackend/backend.hpp>

namespace silkrpc::ethbackend {

class RemoteBackEnd final: public BackEnd {
public:
    explicit RemoteBackEnd(boost::asio::io_context& context, std::shared_ptr<grpc::Channel> channel, agrpc::GrpcContext& grpc_context);

    explicit RemoteBackEnd(boost::asio::io_context::executor_type executor, std::unique_ptr<::remote::ETHBACKEND::StubInterface> stub,
        agrpc::GrpcContext& grpc_context);

    ~RemoteBackEnd();

    boost::asio::awaitable<evmc::address> etherbase();
    boost::asio::awaitable<uint64_t> protocol_version();
    boost::asio::awaitable<uint64_t> net_version();
    boost::asio::awaitable<std::string> client_version();
    boost::asio::awaitable<uint64_t> net_peer_count();
    boost::asio::awaitable<ExecutionPayload> engine_get_payload_v1(uint64_t payload_id);
    boost::asio::awaitable<PayloadStatus> engine_new_payload_v1(ExecutionPayload payload);
    boost::asio::awaitable<ForkChoiceUpdatedReply> engine_forkchoice_updated_v1( ForkChoiceUpdatedRequest forkchoice_updated_request);
    boost::asio::awaitable<std::vector<NodeInfo>> engine_node_info();

private:
    evmc::address address_from_H160(const types::H160& h160);
    silkworm::Bytes bytes_from_H128(const types::H128& h128);
    types::H128* H128_from_bytes(const uint8_t* bytes);
    types::H160* H160_from_address(const evmc::address& address);
    types::H256* H256_from_bytes(const uint8_t* bytes);
    silkworm::Bytes bytes_from_H256(const types::H256& h256);
    intx::uint256 uint256_from_H256(const types::H256& h256);
    types::H256* H256_from_uint256(const intx::uint256& n);
    evmc::bytes32 bytes32_from_H256(const types::H256& h256);
    types::H512* H512_from_bytes(const uint8_t* bytes);
    silkworm::Bytes bytes_from_H512(types::H512& h512);
    types::H1024* H1024_from_bytes(const uint8_t* bytes);
    silkworm::Bytes bytes_from_H1024(types::H1024& h1024);
    types::H2048* H2048_from_bytes(const uint8_t* bytes);
    silkworm::Bytes bytes_from_H2048(types::H2048& h2048);

    ExecutionPayload decode_execution_payload(const types::ExecutionPayload& execution_payload_grpc);
    types::ExecutionPayload encode_execution_payload(const ExecutionPayload& execution_payload);
    remote::EngineForkChoiceState* encode_forkchoice_state(const ForkChoiceState& forkchoice_state);
    remote::EnginePayloadAttributes* encode_payload_attributes(const PayloadAttributes& payload_attributes);
    remote::EngineForkChoiceUpdatedRequest encode_forkchoice_updated_request(const ForkChoiceUpdatedRequest& forkchoice_updated_request);
    PayloadStatus decode_payload_status(const remote::EnginePayloadStatus& payload_status_grpc);
    std::string decode_status_message(const remote::EngineStatus& status);

    boost::asio::io_context::executor_type executor_;
    std::unique_ptr<::remote::ETHBACKEND::StubInterface> stub_;
    agrpc::GrpcContext& grpc_context_;
};

} // namespace silkrpc::ethbackend

