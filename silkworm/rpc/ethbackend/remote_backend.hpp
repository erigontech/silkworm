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
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/io_context.hpp>
#include <evmc/evmc.hpp>
#include <gsl/pointers>
#include <nlohmann/json.hpp>

#include <silkworm/interfaces/remote/ethbackend.grpc.pb.h>
#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/rpc/ethbackend/backend.hpp>
#include <silkworm/rpc/types/execution_payload.hpp>

namespace silkworm::rpc::ethbackend {

class RemoteBackEnd final : public BackEnd {
  public:
    RemoteBackEnd(boost::asio::io_context& context, const std::shared_ptr<grpc::Channel>& channel,
                  agrpc::GrpcContext& grpc_context);
    RemoteBackEnd(boost::asio::io_context::executor_type executor,
                  std::unique_ptr<::remote::ETHBACKEND::StubInterface> stub,
                  agrpc::GrpcContext& grpc_context);
    ~RemoteBackEnd() override = default;

    Task<evmc::address> etherbase() override;
    Task<uint64_t> protocol_version() override;
    Task<uint64_t> net_version() override;
    Task<std::string> client_version() override;
    Task<uint64_t> net_peer_count() override;
    Task<ExecutionPayloadAndValue> engine_get_payload(uint64_t payload_id) override;
    Task<PayloadStatus> engine_new_payload(const ExecutionPayload& payload) override;
    Task<ForkChoiceUpdatedReply> engine_forkchoice_updated(const ForkChoiceUpdatedRequest& fcu_request) override;
    Task<ExecutionPayloadBodies> engine_get_payload_bodies_by_hash(const std::vector<Hash>& block_hashes) override;
    Task<ExecutionPayloadBodies> engine_get_payload_bodies_by_range(BlockNum start, uint64_t count) override;
    Task<NodeInfos> engine_node_info() override;
    Task<PeerInfos> peers() override;
    Task<bool> get_block(BlockNum block_number, const HashAsSpan& hash, bool read_senders, silkworm::Block& block) override;
    Task<BlockNum> get_block_number_from_txn_hash(const HashAsSpan& hash) override;

  private:
    static ExecutionPayload decode_execution_payload(const ::types::ExecutionPayload& grpc_payload);
    static ::types::ExecutionPayload encode_execution_payload(const ExecutionPayload& execution_payload);
    static gsl::owner<::remote::EngineForkChoiceState*> encode_forkchoice_state(const ForkChoiceState&);
    static gsl::owner<::remote::EnginePayloadAttributes*> encode_payload_attributes(const PayloadAttributes& payload_attributes);
    static ::remote::EngineForkChoiceUpdatedRequest encode_forkchoice_updated_request(const ForkChoiceUpdatedRequest& fcu_request);
    static std::vector<Bytes> decode(const ::google::protobuf::RepeatedPtrField<std::string>& grpc_txs);
    static std::vector<Withdrawal> decode(const ::google::protobuf::RepeatedPtrField<::types::Withdrawal>& grpc_withdrawals);
    static PayloadStatus decode_payload_status(const ::remote::EnginePayloadStatus& payload_status_grpc);
    static std::string decode_status_message(const ::remote::EngineStatus& status);

    boost::asio::io_context::executor_type executor_;
    std::unique_ptr<::remote::ETHBACKEND::StubInterface> stub_;
    agrpc::GrpcContext& grpc_context_;
};

}  // namespace silkworm::rpc::ethbackend
