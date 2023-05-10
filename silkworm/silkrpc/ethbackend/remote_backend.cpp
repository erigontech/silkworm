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

#include "remote_backend.hpp"

#include <optional>
#include <vector>

#include <boost/endian/conversion.hpp>
#include <grpcpp/grpcpp.h>
#include <nlohmann/json.hpp>

#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/silkrpc/common/clock_time.hpp>
#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/grpc/unary_rpc.hpp>
#include <silkworm/silkrpc/json/types.hpp>

namespace silkworm::rpc::ethbackend {

RemoteBackEnd::RemoteBackEnd(boost::asio::io_context& context, const std::shared_ptr<grpc::Channel>& channel,
                             agrpc::GrpcContext& grpc_context)
    : RemoteBackEnd(context.get_executor(), ::remote::ETHBACKEND::NewStub(channel), grpc_context) {}

RemoteBackEnd::RemoteBackEnd(boost::asio::io_context::executor_type executor,
                             std::unique_ptr<::remote::ETHBACKEND::StubInterface> stub,
                             agrpc::GrpcContext& grpc_context)
    : executor_(std::move(executor)), stub_(std::move(stub)), grpc_context_(grpc_context) {
    SILKRPC_TRACE << "RemoteBackEnd::ctor " << this << "\n";
}

RemoteBackEnd::~RemoteBackEnd() {
    SILKRPC_TRACE << "RemoteBackEnd::dtor " << this << "\n";
}

awaitable<evmc::address> RemoteBackEnd::etherbase() {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncEtherbase> eb_rpc{*stub_, grpc_context_};
    const auto reply = co_await eb_rpc.finish_on(executor_, ::remote::EtherbaseRequest{});
    evmc::address evmc_address;
    if (reply.has_address()) {
        const auto h160_address = reply.address();
        evmc_address = address_from_H160(h160_address);
    }
    SILKRPC_DEBUG << "RemoteBackEnd::etherbase address=" << evmc_address << " t=" << clock_time::since(start_time) << "\n";
    co_return evmc_address;
}

awaitable<uint64_t> RemoteBackEnd::protocol_version() {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncProtocolVersion> pv_rpc{*stub_, grpc_context_};
    const auto reply = co_await pv_rpc.finish_on(executor_, ::remote::ProtocolVersionRequest{});
    const auto pv = reply.id();
    SILKRPC_DEBUG << "RemoteBackEnd::protocol_version version=" << pv << " t=" << clock_time::since(start_time) << "\n";
    co_return pv;
}

awaitable<uint64_t> RemoteBackEnd::net_version() {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncNetVersion> nv_rpc{*stub_, grpc_context_};
    const auto reply = co_await nv_rpc.finish_on(executor_, ::remote::NetVersionRequest{});
    const auto nv = reply.id();
    SILKRPC_DEBUG << "RemoteBackEnd::net_version version=" << nv << " t=" << clock_time::since(start_time) << "\n";
    co_return nv;
}

awaitable<std::string> RemoteBackEnd::client_version() {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncClientVersion> cv_rpc{*stub_, grpc_context_};
    const auto reply = co_await cv_rpc.finish_on(executor_, ::remote::ClientVersionRequest{});
    const auto cv = reply.node_name();
    SILKRPC_DEBUG << "RemoteBackEnd::client_version version=" << cv << " t=" << clock_time::since(start_time) << "\n";
    co_return cv;
}

awaitable<uint64_t> RemoteBackEnd::net_peer_count() {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncNetPeerCount> npc_rpc{*stub_, grpc_context_};
    const auto reply = co_await npc_rpc.finish_on(executor_, ::remote::NetPeerCountRequest{});
    const auto count = reply.count();
    SILKRPC_DEBUG << "RemoteBackEnd::net_peer_count count=" << count << " t=" << clock_time::since(start_time) << "\n";
    co_return count;
}

awaitable<NodeInfos> RemoteBackEnd::engine_node_info() {
    NodeInfos node_info_list;
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncNodeInfo> ni_rpc{*stub_, grpc_context_};
    const auto reply = co_await ni_rpc.finish_on(executor_, ::remote::NodesInfoRequest{});
    for (int i = 0; i < reply.nodes_info_size(); i++) {
        NodeInfo node_info;
        const auto backend_node_info = reply.nodes_info(i);
        node_info.id = backend_node_info.id();
        node_info.name = backend_node_info.name();
        node_info.enode = backend_node_info.enode();
        node_info.enr = backend_node_info.enr();
        node_info.listener_addr = backend_node_info.listener_addr();
        node_info.protocols = backend_node_info.protocols();
        if (backend_node_info.has_ports()) {
            const auto ports = backend_node_info.ports();
            node_info.ports.discovery = ports.discovery();
            node_info.ports.listener = ports.listener();
        }
        node_info_list.push_back(node_info);
    }
    SILKRPC_DEBUG << "RemoteBackEnd::engine_node_info t=" << clock_time::since(start_time) << "\n";
    co_return node_info_list;
}

awaitable<ExecutionPayload> RemoteBackEnd::engine_get_payload_v1(uint64_t payload_id) {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncEngineGetPayload> npc_rpc{*stub_, grpc_context_};
    ::remote::EngineGetPayloadRequest req;
    req.set_payload_id(payload_id);
    const auto reply = co_await npc_rpc.finish_on(executor_, req);
    auto execution_payload{decode_execution_payload(reply.execution_payload())};
    SILKRPC_DEBUG << "RemoteBackEnd::engine_get_payload_v1 data=" << execution_payload << " t=" << clock_time::since(start_time) << "\n";
    co_return execution_payload;
}

awaitable<PayloadStatus> RemoteBackEnd::engine_new_payload_v1(const ExecutionPayload& payload) {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncEngineNewPayload> npc_rpc{*stub_, grpc_context_};
    auto req{encode_execution_payload(payload)};
    const auto reply = co_await npc_rpc.finish_on(executor_, req);
    PayloadStatus payload_status = decode_payload_status(reply);
    SILKRPC_DEBUG << "RemoteBackEnd::engine_new_payload_v1 data=" << payload_status << " t=" << clock_time::since(start_time) << "\n";
    co_return payload_status;
}

awaitable<ForkChoiceUpdatedReply> RemoteBackEnd::engine_forkchoice_updated_v1(const ForkChoiceUpdatedRequest& fcu_request) {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncEngineForkChoiceUpdated> fcu_rpc{*stub_, grpc_context_};
    const auto req{encode_forkchoice_updated_request(fcu_request)};
    const auto reply = co_await fcu_rpc.finish_on(executor_, req);
    PayloadStatus payload_status = decode_payload_status(reply.payload_status());
    ForkChoiceUpdatedReply forkchoice_updated_reply{
        .payload_status = payload_status,
        .payload_id = std::nullopt};
    // set payload id (if there is one)
    if (reply.payload_id() != 0) {
        forkchoice_updated_reply.payload_id = reply.payload_id();
    }
    SILKRPC_DEBUG << "RemoteBackEnd::engine_forkchoice_updated_v1 data=" << payload_status << " t=" << clock_time::since(start_time) << "\n";
    co_return forkchoice_updated_reply;
}

awaitable<PeerInfos> RemoteBackEnd::peers() {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncPeers> peers_rpc{*stub_, grpc_context_};
    ::google::protobuf::Empty request;
    const auto reply = co_await peers_rpc.finish_on(executor_, request);
    PeerInfos peer_infos;
    peer_infos.reserve(static_cast<std::size_t>(reply.peers_size()));
    for (const auto& peer : reply.peers()) {
        PeerInfo peer_info{
            .id = peer.id(),
            .name = peer.name(),
            .enode = peer.enode(),
            .enr = peer.enr(),
            .caps = {peer.caps().begin(), peer.caps().end()},
            .local_address = peer.conn_local_addr(),
            .remote_address = peer.conn_remote_addr(),
            .is_connection_inbound = peer.conn_is_inbound(),
            .is_connection_trusted = peer.conn_is_trusted(),
            .is_connection_static = peer.conn_is_static(),
        };
        peer_infos.push_back(peer_info);
    }
    SILKRPC_DEBUG << "RemoteBackEnd::peers t=" << clock_time::since(start_time) << "\n";
    co_return peer_infos;
}

ExecutionPayload RemoteBackEnd::decode_execution_payload(const ::types::ExecutionPayload& execution_payload_grpc) {
    const auto& state_root_h256{execution_payload_grpc.state_root()};
    const auto& receipts_root_h256{execution_payload_grpc.receipt_root()};
    const auto& block_hash_h256{execution_payload_grpc.block_hash()};
    const auto& parent_hash_h256{execution_payload_grpc.parent_hash()};
    const auto& prev_randao_h256{execution_payload_grpc.prev_randao()};
    const auto& base_fee_h256{execution_payload_grpc.base_fee_per_gas()};
    const auto& logs_bloom_h2048{execution_payload_grpc.logs_bloom()};
    const auto& extra_data_string{execution_payload_grpc.extra_data()};  // []byte becomes std::string in silkrpc protobuf
    // Convert h2048 to a bloom
    silkworm::Bloom bloom;
    std::memcpy(bloom.data(), bytes_from_H2048(logs_bloom_h2048).data(), bloom.size());
    // Convert transactions in std::string to silkworm::Bytes
    std::vector<Bytes> transactions;
    for (const auto& transaction_string : execution_payload_grpc.transactions()) {
        transactions.push_back(bytes_of_string(transaction_string));
    }

    // Assembling the execution_payload data structure
    return ExecutionPayload{
        .number = execution_payload_grpc.block_number(),
        .timestamp = execution_payload_grpc.timestamp(),
        .gas_limit = execution_payload_grpc.gas_limit(),
        .gas_used = execution_payload_grpc.gas_used(),
        .suggested_fee_recipient = address_from_H160(execution_payload_grpc.coinbase()),
        .state_root = bytes32_from_H256(state_root_h256),
        .receipts_root = bytes32_from_H256(receipts_root_h256),
        .parent_hash = bytes32_from_H256(parent_hash_h256),
        .block_hash = bytes32_from_H256(block_hash_h256),
        .prev_randao = bytes32_from_H256(prev_randao_h256),
        .base_fee = uint256_from_H256(base_fee_h256),
        .logs_bloom = bloom,
        .extra_data = silkworm::bytes_of_string(extra_data_string),
        .transactions = transactions};
}

::types::ExecutionPayload RemoteBackEnd::encode_execution_payload(const ExecutionPayload& execution_payload) {
    ::types::ExecutionPayload execution_payload_grpc;
    // Numerical parameters
    execution_payload_grpc.set_block_number(execution_payload.number);
    execution_payload_grpc.set_timestamp(execution_payload.timestamp);
    execution_payload_grpc.set_gas_limit(execution_payload.gas_limit);
    execution_payload_grpc.set_gas_used(execution_payload.gas_used);
    // coinbase
    execution_payload_grpc.set_allocated_coinbase(H160_from_address(execution_payload.suggested_fee_recipient).release());
    // 32-bytes parameters
    execution_payload_grpc.set_allocated_receipt_root(H256_from_bytes({execution_payload.receipts_root.bytes, kHashLength}).release());
    execution_payload_grpc.set_allocated_state_root(H256_from_bytes({execution_payload.state_root.bytes, kHashLength}).release());
    execution_payload_grpc.set_allocated_parent_hash(H256_from_bytes({execution_payload.parent_hash.bytes, kHashLength}).release());
    execution_payload_grpc.set_allocated_block_hash(H256_from_bytes({execution_payload.block_hash.bytes, kHashLength}).release());
    execution_payload_grpc.set_allocated_prev_randao(H256_from_bytes({execution_payload.prev_randao.bytes, kHashLength}).release());
    execution_payload_grpc.set_allocated_base_fee_per_gas(H256_from_uint256(execution_payload.base_fee).release());
    // Logs Bloom
    execution_payload_grpc.set_allocated_logs_bloom(H2048_from_bytes(execution_payload.logs_bloom).release());
    // String-like parameters
    for (auto transaction_bytes : execution_payload.transactions) {
        execution_payload_grpc.add_transactions(std::string(transaction_bytes.begin(), transaction_bytes.end()));
    }
    execution_payload_grpc.set_extra_data(std::string(execution_payload.extra_data.begin(), execution_payload.extra_data.end()));
    return execution_payload_grpc;
}

::remote::EngineForkChoiceState* RemoteBackEnd::encode_forkchoice_state(const ForkChoiceState& fcs) {
    auto fcs_grpc = new ::remote::EngineForkChoiceState();
    // 32-bytes parameters
    fcs_grpc->set_allocated_head_block_hash(H256_from_bytes({fcs.head_block_hash.bytes, kHashLength}).release());
    fcs_grpc->set_allocated_safe_block_hash(H256_from_bytes({fcs.safe_block_hash.bytes, kHashLength}).release());
    fcs_grpc->set_allocated_finalized_block_hash(H256_from_bytes({fcs.finalized_block_hash.bytes, kHashLength}).release());
    return fcs_grpc;
}

::remote::EnginePayloadAttributes* RemoteBackEnd::encode_payload_attributes(const PayloadAttributes& epa) {
    auto epa_grpc = new ::remote::EnginePayloadAttributes();
    // TODO(yperbasis) support v2 (withdrawals) as well
    epa_grpc->set_version(1);
    // Numerical parameters
    epa_grpc->set_timestamp(epa.timestamp);
    // 32-bytes parameters
    epa_grpc->set_allocated_prev_randao(H256_from_bytes({epa.prev_randao.bytes, kHashLength}).release());
    // Address parameters
    epa_grpc->set_allocated_suggested_fee_recipient(H160_from_address(epa.suggested_fee_recipient).release());
    return epa_grpc;
}

::remote::EngineForkChoiceUpdatedRequest RemoteBackEnd::encode_forkchoice_updated_request(const ForkChoiceUpdatedRequest& fcu_request) {
    ::remote::EngineForkChoiceUpdatedRequest fcu_request_grpc;
    ::remote::EngineForkChoiceState* forkchoice_state_grpc = RemoteBackEnd::encode_forkchoice_state(fcu_request.fork_choice_state);

    fcu_request_grpc.set_allocated_forkchoice_state(forkchoice_state_grpc);
    if (fcu_request.payload_attributes != std::nullopt) {
        ::remote::EnginePayloadAttributes* payload_attributes_grpc = encode_payload_attributes(fcu_request.payload_attributes.value());
        fcu_request_grpc.set_allocated_payload_attributes(payload_attributes_grpc);
    }
    return fcu_request_grpc;
}

PayloadStatus RemoteBackEnd::decode_payload_status(const ::remote::EnginePayloadStatus& payload_status_grpc) {
    PayloadStatus payload_status;
    payload_status.status = decode_status_message(payload_status_grpc.status());
    // Set LatestValidHash (if there is one)
    if (payload_status_grpc.has_latest_valid_hash()) {
        payload_status.latest_valid_hash = bytes32_from_H256(payload_status_grpc.latest_valid_hash());
    }
    // Set ValidationError (if there is one)
    const auto& validation_error{payload_status_grpc.validation_error()};
    if (!validation_error.empty()) {
        payload_status.validation_error = validation_error;
    }
    return payload_status;
}

std::string RemoteBackEnd::decode_status_message(const ::remote::EngineStatus& status) {
    switch (status) {
        case ::remote::EngineStatus::VALID:
            return "VALID";
        case ::remote::EngineStatus::SYNCING:
            return "SYNCING";
        case ::remote::EngineStatus::ACCEPTED:
            return "ACCEPTED";
        case ::remote::EngineStatus::INVALID_BLOCK_HASH:
            return "INVALID_BLOCK_HASH";
        default:
            return "INVALID";
    }
}

}  // namespace silkworm::rpc::ethbackend
