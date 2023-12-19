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

#include <silkworm/core/types/address.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/rpc/common/clock_time.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/grpc/unary_rpc.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc::ethbackend {

RemoteBackEnd::RemoteBackEnd(boost::asio::io_context& context, const std::shared_ptr<grpc::Channel>& channel,
                             agrpc::GrpcContext& grpc_context)
    : RemoteBackEnd(context.get_executor(), ::remote::ETHBACKEND::NewStub(channel), grpc_context) {}

RemoteBackEnd::RemoteBackEnd(boost::asio::io_context::executor_type executor,
                             std::unique_ptr<::remote::ETHBACKEND::StubInterface> stub,
                             agrpc::GrpcContext& grpc_context)
    : executor_(std::move(executor)), stub_(std::move(stub)), grpc_context_(grpc_context) {}

Task<evmc::address> RemoteBackEnd::etherbase() {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncEtherbase> eb_rpc{*stub_, grpc_context_};
    const auto reply = co_await eb_rpc.finish_on(executor_, ::remote::EtherbaseRequest{});
    evmc::address evmc_address;
    if (reply.has_address()) {
        const auto& h160_address = reply.address();
        evmc_address = address_from_H160(h160_address);
    }
    SILK_TRACE << "RemoteBackEnd::etherbase address=" << evmc_address << " t=" << clock_time::since(start_time);
    co_return evmc_address;
}

Task<uint64_t> RemoteBackEnd::protocol_version() {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncProtocolVersion> pv_rpc{*stub_, grpc_context_};
    const auto reply = co_await pv_rpc.finish_on(executor_, ::remote::ProtocolVersionRequest{});
    const auto pv = reply.id();
    SILK_TRACE << "RemoteBackEnd::protocol_version version=" << pv << " t=" << clock_time::since(start_time);
    co_return pv;
}

Task<BlockNum> RemoteBackEnd::net_version() {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncNetVersion> nv_rpc{*stub_, grpc_context_};
    const auto reply = co_await nv_rpc.finish_on(executor_, ::remote::NetVersionRequest{});
    const auto nv = reply.id();
    SILK_TRACE << "RemoteBackEnd::net_version version=" << nv << " t=" << clock_time::since(start_time);
    co_return nv;
}

Task<std::string> RemoteBackEnd::client_version() {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncClientVersion> cv_rpc{*stub_, grpc_context_};
    const auto reply = co_await cv_rpc.finish_on(executor_, ::remote::ClientVersionRequest{});
    const auto& cv = reply.node_name();
    SILK_TRACE << "RemoteBackEnd::client_version version=" << cv << " t=" << clock_time::since(start_time);
    co_return cv;
}

Task<uint64_t> RemoteBackEnd::net_peer_count() {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncNetPeerCount> npc_rpc{*stub_, grpc_context_};
    const auto reply = co_await npc_rpc.finish_on(executor_, ::remote::NetPeerCountRequest{});
    const auto count = reply.count();
    SILK_TRACE << "RemoteBackEnd::net_peer_count count=" << count << " t=" << clock_time::since(start_time);
    co_return count;
}

Task<NodeInfos> RemoteBackEnd::engine_node_info() {
    NodeInfos node_info_list;
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncNodeInfo> ni_rpc{*stub_, grpc_context_};
    const auto reply = co_await ni_rpc.finish_on(executor_, ::remote::NodesInfoRequest{});
    for (int i = 0; i < reply.nodes_info_size(); i++) {
        NodeInfo node_info;
        const auto& backend_node_info = reply.nodes_info(i);
        node_info.id = backend_node_info.id();
        node_info.name = backend_node_info.name();
        node_info.enode = backend_node_info.enode();
        node_info.enr = backend_node_info.enr();
        node_info.listener_addr = backend_node_info.listener_addr();
        node_info.protocols = backend_node_info.protocols();
        if (backend_node_info.has_ports()) {
            const auto& ports = backend_node_info.ports();
            node_info.ports.discovery = ports.discovery();
            node_info.ports.listener = ports.listener();
        }
        node_info_list.push_back(node_info);
    }
    SILK_TRACE << "RemoteBackEnd::engine_node_info t=" << clock_time::since(start_time);
    co_return node_info_list;
}

Task<ExecutionPayloadAndValue> RemoteBackEnd::engine_get_payload(uint64_t payload_id) {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncEngineGetPayload> npc_rpc{*stub_, grpc_context_};
    ::remote::EngineGetPayloadRequest req;
    req.set_payload_id(payload_id);
    const auto reply = co_await npc_rpc.finish_on(executor_, req);
    const auto payload{decode_execution_payload(reply.execution_payload())};
    const auto value{uint256_from_H256(reply.block_value())};
    SILK_TRACE << "RemoteBackEnd::engine_get_payload data=" << payload << " value=" << value << " t=" << clock_time::since(start_time);
    co_return ExecutionPayloadAndValue{payload, value};
}

Task<PayloadStatus> RemoteBackEnd::engine_new_payload(const ExecutionPayload& payload) {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncEngineNewPayload> npc_rpc{*stub_, grpc_context_};
    auto req{encode_execution_payload(payload)};
    const auto reply = co_await npc_rpc.finish_on(executor_, req);
    PayloadStatus payload_status = decode_payload_status(reply);
    SILK_TRACE << "RemoteBackEnd::engine_new_payload data=" << payload_status << " t=" << clock_time::since(start_time);
    co_return payload_status;
}

Task<ForkChoiceUpdatedReply> RemoteBackEnd::engine_forkchoice_updated(const ForkChoiceUpdatedRequest& fcu_request) {
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
    SILK_TRACE << "RemoteBackEnd::engine_forkchoice_updated data=" << payload_status << " t=" << clock_time::since(start_time);
    co_return forkchoice_updated_reply;
}

Task<ExecutionPayloadBodies> RemoteBackEnd::engine_get_payload_bodies_by_hash(const std::vector<Hash>& block_hashes) {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncEngineGetPayloadBodiesByHashV1> gpb_rpc{*stub_, grpc_context_};
    ::remote::EngineGetPayloadBodiesByHashV1Request request;
    for (const auto& bh : block_hashes) {
        H256_from_bytes32(bh, request.add_hashes());
    }
    const auto reply = co_await gpb_rpc.finish_on(executor_, request);
    ExecutionPayloadBodies payload_bodies;
    payload_bodies.reserve(static_cast<std::size_t>(reply.bodies_size()));
    for (const auto& body : reply.bodies()) {
        std::vector<Bytes> transactions{decode(body.transactions())};
        std::vector<Withdrawal> withdrawals{decode(body.withdrawals())};
        ExecutionPayloadBody payload_body{std::move(transactions), std::move(withdrawals)};
        payload_bodies.push_back(std::move(payload_body));
    }
    SILK_TRACE << "RemoteBackEnd::engine_get_payload_bodies_by_hash #bodies=" << payload_bodies.size() << " t=" << clock_time::since(start_time);
    co_return payload_bodies;
}

Task<ExecutionPayloadBodies> RemoteBackEnd::engine_get_payload_bodies_by_range(BlockNum start, uint64_t count) {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncEngineGetPayloadBodiesByRangeV1> gpb_rpc{*stub_, grpc_context_};
    ::remote::EngineGetPayloadBodiesByRangeV1Request request;
    request.set_start(start);
    request.set_count(count);
    const auto reply = co_await gpb_rpc.finish_on(executor_, request);
    ExecutionPayloadBodies payload_bodies;
    payload_bodies.reserve(static_cast<std::size_t>(reply.bodies_size()));
    for (const auto& body : reply.bodies()) {
        std::vector<Bytes> transactions{decode(body.transactions())};
        std::vector<Withdrawal> withdrawals{decode(body.withdrawals())};
        ExecutionPayloadBody payload_body{std::move(transactions), std::move(withdrawals)};
        payload_bodies.push_back(std::move(payload_body));
    }
    SILK_TRACE << "RemoteBackEnd::engine_get_payload_bodies_by_range #bodies=" << payload_bodies.size() << " t=" << clock_time::since(start_time);
    co_return payload_bodies;
}

Task<PeerInfos> RemoteBackEnd::peers() {
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
    SILK_TRACE << "RemoteBackEnd::peers t=" << clock_time::since(start_time);
    co_return peer_infos;
}

Task<bool> RemoteBackEnd::get_block(BlockNum block_number, const HashAsSpan& hash, bool read_senders, silkworm::Block& block) {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncBlock> get_block_rpc{*stub_, grpc_context_};
    ::remote::BlockRequest request;
    request.set_block_height(block_number);
    request.set_allocated_block_hash(H256_from_bytes(hash).release());
    const auto reply = co_await get_block_rpc.finish_on(executor_, request);
    ByteView block_rlp{byte_view_of_string(reply.block_rlp())};
    if (const auto decode_result{rlp::decode(block_rlp, block)}; !decode_result) {
        co_return false;
    }
    if (read_senders) {
        ByteView senders{byte_view_of_string(reply.senders())};
        if (senders.size() % kAddressLength == 0 and senders.size() / kAddressLength == block.transactions.size()) {
            std::vector<evmc::address> sender_addresses;
            sender_addresses.reserve(block.transactions.size());
            for (size_t i{0}; i < block.transactions.size(); ++i) {
                ByteView sender{senders.substr(i * kAddressLength, kAddressLength)};
                block.transactions[i].set_sender(bytes_to_address(sender));
            }
        }
    }
    SILK_TRACE << "RemoteBackEnd::get_block t=" << clock_time::since(start_time);
    co_return true;
}

Task<BlockNum> RemoteBackEnd::get_block_number_from_txn_hash(const HashAsSpan& hash) {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncTxnLookup> txn_lookup_rpc{*stub_, grpc_context_};
    ::remote::TxnLookupRequest request;
    request.set_allocated_txn_hash(H256_from_bytes(hash).release());
    const auto reply = co_await txn_lookup_rpc.finish_on(executor_, request);
    auto bn = reply.block_number();
    SILK_TRACE << "RemoteBackEnd::get_block_number_from_txn_hash bn=" << bn << " t=" << clock_time::since(start_time);
    co_return bn;
}

ExecutionPayload RemoteBackEnd::decode_execution_payload(const ::types::ExecutionPayload& grpc_payload) {
    const auto& state_root_h256{grpc_payload.state_root()};
    const auto& receipts_root_h256{grpc_payload.receipt_root()};
    const auto& block_hash_h256{grpc_payload.block_hash()};
    const auto& parent_hash_h256{grpc_payload.parent_hash()};
    const auto& prev_randao_h256{grpc_payload.prev_randao()};
    const auto& base_fee_h256{grpc_payload.base_fee_per_gas()};
    const auto& logs_bloom_h2048{grpc_payload.logs_bloom()};
    const auto& extra_data_string{grpc_payload.extra_data()};  // []byte becomes std::string in silkrpc protobuf
    // Convert h2048 to a bloom
    silkworm::Bloom bloom;
    std::memcpy(bloom.data(), bytes_from_H2048(logs_bloom_h2048).data(), bloom.size());
    // Convert transactions in std::string to silkworm::Bytes
    std::vector<Bytes> transactions{decode(grpc_payload.transactions())};

    // Assembling the execution_payload data structure
    return ExecutionPayload{
        .number = grpc_payload.block_number(),
        .timestamp = grpc_payload.timestamp(),
        .gas_limit = grpc_payload.gas_limit(),
        .gas_used = grpc_payload.gas_used(),
        .suggested_fee_recipient = address_from_H160(grpc_payload.coinbase()),
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

::types::ExecutionPayload RemoteBackEnd::encode_execution_payload(const ExecutionPayload& payload) {
    ::types::ExecutionPayload grpc_payload;
    grpc_payload.set_version(payload.version);
    // Numerical parameters
    grpc_payload.set_block_number(payload.number);
    grpc_payload.set_timestamp(payload.timestamp);
    grpc_payload.set_gas_limit(payload.gas_limit);
    grpc_payload.set_gas_used(payload.gas_used);
    // coinbase
    grpc_payload.set_allocated_coinbase(H160_from_address(payload.suggested_fee_recipient).release());
    // 32-bytes parameters
    grpc_payload.set_allocated_receipt_root(H256_from_bytes({payload.receipts_root.bytes, kHashLength}).release());
    grpc_payload.set_allocated_state_root(H256_from_bytes({payload.state_root.bytes, kHashLength}).release());
    grpc_payload.set_allocated_parent_hash(H256_from_bytes({payload.parent_hash.bytes, kHashLength}).release());
    grpc_payload.set_allocated_block_hash(H256_from_bytes({payload.block_hash.bytes, kHashLength}).release());
    grpc_payload.set_allocated_prev_randao(H256_from_bytes({payload.prev_randao.bytes, kHashLength}).release());
    grpc_payload.set_allocated_base_fee_per_gas(H256_from_uint256(payload.base_fee).release());
    // Logs Bloom
    grpc_payload.set_allocated_logs_bloom(H2048_from_bytes(payload.logs_bloom).release());
    // String-like parameters
    for (auto transaction_bytes : payload.transactions) {
        grpc_payload.add_transactions(std::string(transaction_bytes.begin(), transaction_bytes.end()));
    }
    grpc_payload.set_extra_data(std::string(payload.extra_data.begin(), payload.extra_data.end()));
    // Withdrawals
    if (payload.withdrawals) {
        for (auto& withdrawal : payload.withdrawals.value()) {
            auto grpc_withdrawal = grpc_payload.add_withdrawals();
            grpc_withdrawal->set_index(withdrawal.index);
            grpc_withdrawal->set_validator_index(withdrawal.validator_index);
            grpc_withdrawal->set_allocated_address(H160_from_address(withdrawal.address).release());
            grpc_withdrawal->set_amount(withdrawal.amount);
        }
    }
    return grpc_payload;
}

gsl::owner<::remote::EngineForkChoiceState*> RemoteBackEnd::encode_forkchoice_state(const ForkChoiceState& fcs) {
    auto fcs_grpc = new ::remote::EngineForkChoiceState();
    // 32-bytes parameters
    fcs_grpc->set_allocated_head_block_hash(H256_from_bytes({fcs.head_block_hash.bytes, kHashLength}).release());
    fcs_grpc->set_allocated_safe_block_hash(H256_from_bytes({fcs.safe_block_hash.bytes, kHashLength}).release());
    fcs_grpc->set_allocated_finalized_block_hash(H256_from_bytes({fcs.finalized_block_hash.bytes, kHashLength}).release());
    return fcs_grpc;
}

gsl::owner<::remote::EnginePayloadAttributes*> RemoteBackEnd::encode_payload_attributes(const PayloadAttributes& payload_attributes) {
    auto epa_grpc = new ::remote::EnginePayloadAttributes();
    epa_grpc->set_version(payload_attributes.version);
    // Numerical parameters
    epa_grpc->set_timestamp(payload_attributes.timestamp);
    // 32-bytes parameters
    epa_grpc->set_allocated_prev_randao(H256_from_bytes({payload_attributes.prev_randao.bytes, kHashLength}).release());
    // Address parameters
    epa_grpc->set_allocated_suggested_fee_recipient(H160_from_address(payload_attributes.suggested_fee_recipient).release());
    // Withdrawals
    if (payload_attributes.withdrawals) {
        for (auto& withdrawal : payload_attributes.withdrawals.value()) {
            auto grpc_withdrawal = epa_grpc->add_withdrawals();
            grpc_withdrawal->set_index(withdrawal.index);
            grpc_withdrawal->set_validator_index(withdrawal.validator_index);
            grpc_withdrawal->set_allocated_address(H160_from_address(withdrawal.address).release());
            grpc_withdrawal->set_amount(withdrawal.amount);
        }
    }
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

std::vector<Bytes> RemoteBackEnd::decode(const ::google::protobuf::RepeatedPtrField<std::string>& grpc_txs) {
    // Convert encoded transactions from std::string to Bytes
    std::vector<Bytes> encoded_transactions;
    encoded_transactions.reserve(static_cast<std::size_t>(grpc_txs.size()));
    for (const auto& grpc_tx_string : grpc_txs) {
        encoded_transactions.push_back(bytes_of_string(grpc_tx_string));
    }
    return encoded_transactions;
}

std::vector<Withdrawal> RemoteBackEnd::decode(const ::google::protobuf::RepeatedPtrField<::types::Withdrawal>& grpc_withdrawals) {
    std::vector<Withdrawal> withdrawals;
    withdrawals.reserve(static_cast<std::size_t>(grpc_withdrawals.size()));
    for (auto& grpc_withdrawal : grpc_withdrawals) {
        Withdrawal w{grpc_withdrawal.index(),
                     grpc_withdrawal.validator_index(),
                     address_from_H160(grpc_withdrawal.address()),
                     grpc_withdrawal.amount()};
        withdrawals.emplace_back(w);
    }
    return withdrawals;
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
