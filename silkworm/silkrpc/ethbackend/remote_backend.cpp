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

#include "remote_backend.hpp"

#include <optional>
#include <vector>

#include <boost/endian/conversion.hpp>
#include <grpcpp/grpcpp.h>
#include <nlohmann/json.hpp>

#include <silkworm/silkrpc/grpc/unary_rpc.hpp>
#include <silkworm/silkrpc/common/clock_time.hpp>
#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/config.hpp>
#include <silkworm/silkrpc/json/types.hpp>

namespace silkrpc::ethbackend {

RemoteBackEnd::RemoteBackEnd(boost::asio::io_context& context, std::shared_ptr<grpc::Channel> channel, agrpc::GrpcContext& grpc_context)
    : RemoteBackEnd(context.get_executor(), ::remote::ETHBACKEND::NewStub(channel), grpc_context) {}

RemoteBackEnd::RemoteBackEnd(boost::asio::io_context::executor_type executor, std::unique_ptr<::remote::ETHBACKEND::StubInterface> stub,
    agrpc::GrpcContext& grpc_context) : executor_(executor), stub_(std::move(stub)), grpc_context_(grpc_context) {
    SILKRPC_TRACE << "RemoteBackEnd::ctor " << this << "\n";
}

RemoteBackEnd::~RemoteBackEnd() {
    SILKRPC_TRACE << "RemoteBackEnd::dtor " << this << "\n";
}

boost::asio::awaitable<evmc::address> RemoteBackEnd::etherbase() {
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

boost::asio::awaitable<uint64_t> RemoteBackEnd::protocol_version() {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncProtocolVersion> pv_rpc{*stub_, grpc_context_};
    const auto reply = co_await pv_rpc.finish_on(executor_, ::remote::ProtocolVersionRequest{});
    const auto pv = reply.id();
    SILKRPC_DEBUG << "RemoteBackEnd::protocol_version version=" << pv << " t=" << clock_time::since(start_time) << "\n";
    co_return pv;
}

boost::asio::awaitable<uint64_t> RemoteBackEnd::net_version() {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncNetVersion> nv_rpc{*stub_, grpc_context_};
    const auto reply = co_await nv_rpc.finish_on(executor_, ::remote::NetVersionRequest{});
    const auto nv = reply.id();
    SILKRPC_DEBUG << "RemoteBackEnd::net_version version=" << nv << " t=" << clock_time::since(start_time) << "\n";
    co_return nv;
}

boost::asio::awaitable<std::string> RemoteBackEnd::client_version() {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncClientVersion> cv_rpc{*stub_, grpc_context_};
    const auto reply = co_await cv_rpc.finish_on(executor_, ::remote::ClientVersionRequest{});
    const auto cv = reply.nodename();
    SILKRPC_DEBUG << "RemoteBackEnd::client_version version=" << cv << " t=" << clock_time::since(start_time) << "\n";
    co_return cv;
}

boost::asio::awaitable<uint64_t> RemoteBackEnd::net_peer_count() {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncNetPeerCount> npc_rpc{*stub_, grpc_context_};
    const auto reply = co_await npc_rpc.finish_on(executor_, ::remote::NetPeerCountRequest{});
    const auto count = reply.count();
    SILKRPC_DEBUG << "RemoteBackEnd::net_peer_count count=" << count << " t=" << clock_time::since(start_time) << "\n";
    co_return count;
}

boost::asio::awaitable<std::vector<NodeInfo>> RemoteBackEnd::engine_node_info() {
    std::vector<NodeInfo> node_info_list;
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncNodeInfo> ni_rpc{*stub_, grpc_context_};
    const auto reply = co_await ni_rpc.finish_on(executor_, ::remote::NodesInfoRequest{});
    for (int i = 0; i < reply.nodesinfo_size(); i++) {
        NodeInfo node_info;
        const auto backend_node_info = reply.nodesinfo(i);
        node_info.id = backend_node_info.id();
        node_info.name = backend_node_info.name();
        node_info.enode = backend_node_info.enode();
        node_info.enr = backend_node_info.enr();
        node_info.listener_addr = backend_node_info.listeneraddr();
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

boost::asio::awaitable<ExecutionPayload> RemoteBackEnd::engine_get_payload_v1(uint64_t payload_id) {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncEngineGetPayloadV1> npc_rpc{*stub_, grpc_context_};
    ::remote::EngineGetPayloadRequest req;
    req.set_payloadid(payload_id);
    const auto reply = co_await npc_rpc.finish_on(executor_, req);
    auto execution_payload{decode_execution_payload(reply)};
    SILKRPC_DEBUG << "RemoteBackEnd::engine_get_payload_v1 data=" << execution_payload << " t=" << clock_time::since(start_time) << "\n";
    co_return execution_payload;
}

boost::asio::awaitable<PayloadStatus> RemoteBackEnd::engine_new_payload_v1(ExecutionPayload payload) {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncEngineNewPayloadV1> npc_rpc{*stub_, grpc_context_};
    auto req{encode_execution_payload(payload)};
    const auto reply = co_await npc_rpc.finish_on(executor_, req);
    PayloadStatus payload_status = decode_payload_status(reply);
    SILKRPC_DEBUG << "RemoteBackEnd::engine_new_payload_v1 data=" << payload_status << " t=" << clock_time::since(start_time) << "\n";
    co_return payload_status;
}

boost::asio::awaitable<ForkChoiceUpdatedReply> RemoteBackEnd::engine_forkchoice_updated_v1(
    ForkChoiceUpdatedRequest forkchoice_updated_request) {
    const auto start_time = clock_time::now();
    UnaryRpc<&::remote::ETHBACKEND::StubInterface::AsyncEngineForkChoiceUpdatedV1> fcu_rpc{*stub_, grpc_context_};
    const auto req{encode_forkchoice_updated_request(forkchoice_updated_request)};
    const auto reply = co_await fcu_rpc.finish_on(executor_, req);
    PayloadStatus payload_status = decode_payload_status(reply.payloadstatus());
    ForkChoiceUpdatedReply forkchoice_updated_reply{
        .payload_status = payload_status,
        .payload_id = std::nullopt
    };
    // set payload id (if there is one)
    if (reply.payloadid() != 0) {
        forkchoice_updated_reply.payload_id = reply.payloadid();
    }
    SILKRPC_DEBUG << "RemoteBackEnd::engine_forkchoice_updated_v1 data=" << payload_status << " t=" << clock_time::since(start_time) << "\n";
    co_return forkchoice_updated_reply;
}

evmc::address RemoteBackEnd::address_from_H160(const types::H160& h160) {
    uint64_t hi_hi = h160.hi().hi();
    uint64_t hi_lo = h160.hi().lo();
    uint32_t lo = h160.lo();
    evmc::address address{};
    boost::endian::store_big_u64(address.bytes +  0, hi_hi);
    boost::endian::store_big_u64(address.bytes +  8, hi_lo);
    boost::endian::store_big_u32(address.bytes + 16, lo);
    return address;
}

silkworm::Bytes RemoteBackEnd::bytes_from_H128(const types::H128& h128) {
    silkworm::Bytes bytes(16, '\0');
    boost::endian::store_big_u64(&bytes[0], h128.hi());
    boost::endian::store_big_u64(&bytes[8], h128.lo());
    return bytes;
}

types::H128* RemoteBackEnd::H128_from_bytes(const uint8_t* bytes) {
    auto h128{new types::H128()};
    h128->set_hi(boost::endian::load_big_u64(bytes));
    h128->set_lo(boost::endian::load_big_u64(bytes + 8));
    return h128;
}

types::H160* RemoteBackEnd::H160_from_address(const evmc::address& address) {
    auto h160{new types::H160()};
    auto hi{H128_from_bytes(address.bytes)};
    h160->set_allocated_hi(hi);
    h160->set_lo(boost::endian::load_big_u32(address.bytes + 16));
    return h160;
}

types::H256* RemoteBackEnd::H256_from_bytes(const uint8_t* bytes) {
    auto h256{new types::H256()};
    auto hi{H128_from_bytes(bytes)};
    auto lo{H128_from_bytes(bytes + 16)};
    h256->set_allocated_hi(hi);
    h256->set_allocated_lo(lo);
    return h256;
}

silkworm::Bytes RemoteBackEnd::bytes_from_H256(const types::H256& h256) {
    silkworm::Bytes bytes(32, '\0');
    auto hi{h256.hi()};
    auto lo{h256.lo()};
    std::memcpy(&bytes[0], bytes_from_H128(hi).data(), 16);
    std::memcpy(&bytes[16], bytes_from_H128(lo).data(), 16);
    return bytes;
}

intx::uint256 RemoteBackEnd::uint256_from_H256(const types::H256& h256) {
    intx::uint256 n;
    n[3] = h256.hi().hi();
    n[2] = h256.hi().lo();
    n[1] = h256.lo().hi();
    n[0] = h256.lo().lo();
    return n;
}

types::H256* RemoteBackEnd::H256_from_uint256(const intx::uint256& n) {
    auto h256{new types::H256()};
    auto hi{new types::H128()};
    auto lo{new types::H128()};

    hi->set_hi(n[3]);
    hi->set_lo(n[2]);
    lo->set_hi(n[1]);
    lo->set_lo(n[0]);

    h256->set_allocated_hi(hi);
    h256->set_allocated_lo(lo);
    return h256;
}

evmc::bytes32 RemoteBackEnd::bytes32_from_H256(const types::H256& h256) {
    evmc::bytes32 bytes32;
    std::memcpy(bytes32.bytes, bytes_from_H256(h256).data(), 32);
    return bytes32;
}

types::H512* RemoteBackEnd::H512_from_bytes(const uint8_t* bytes) {
    auto h512{new types::H512()};
    auto hi{H256_from_bytes(bytes)};
    auto lo{H256_from_bytes(bytes + 32)};
    h512->set_allocated_hi(hi);
    h512->set_allocated_lo(lo);
    return h512;
}

silkworm::Bytes RemoteBackEnd::bytes_from_H512(types::H512& h512) {
    silkworm::Bytes bytes(64, '\0');
    auto hi{h512.hi()};
    auto lo{h512.lo()};
    std::memcpy(&bytes[0], bytes_from_H256(hi).data(), 32);
    std::memcpy(&bytes[32], bytes_from_H256(lo).data(), 32);
    return bytes;
}

types::H1024* RemoteBackEnd::H1024_from_bytes(const uint8_t* bytes) {
    auto h1024{new types::H1024()};
    auto hi{H512_from_bytes(bytes)};
    auto lo{H512_from_bytes(bytes + 64)};
    h1024->set_allocated_hi(hi);
    h1024->set_allocated_lo(lo);
    return h1024;
}

silkworm::Bytes RemoteBackEnd::bytes_from_H1024(types::H1024& h1024) {
    silkworm::Bytes bytes(128, '\0');
    auto hi{h1024.hi()};
    auto lo{h1024.lo()};
    std::memcpy(&bytes[0], bytes_from_H512(hi).data(), 64);
    std::memcpy(&bytes[64], bytes_from_H512(lo).data(), 64);
    return bytes;
}

types::H2048* RemoteBackEnd::H2048_from_bytes(const uint8_t* bytes) {
    auto h2048{new types::H2048()};
    auto hi{H1024_from_bytes(bytes)};
    auto lo{H1024_from_bytes(bytes + 128)};
    h2048->set_allocated_hi(hi);
    h2048->set_allocated_lo(lo);
    return h2048;
}

silkworm::Bytes RemoteBackEnd::bytes_from_H2048(types::H2048& h2048) {
    silkworm::Bytes bytes(256, '\0');
    auto hi{h2048.hi()};
    auto lo{h2048.lo()};
    std::memcpy(&bytes[0], bytes_from_H1024(hi).data(), 128);
    std::memcpy(&bytes[128], bytes_from_H1024(lo).data(), 128);
    return bytes;
}

ExecutionPayload RemoteBackEnd::decode_execution_payload(const types::ExecutionPayload& execution_payload_grpc) {
    auto state_root_h256{execution_payload_grpc.stateroot()};
    auto receipts_root_h256{execution_payload_grpc.receiptroot()};
    auto block_hash_h256{execution_payload_grpc.blockhash()};
    auto parent_hash_h256{execution_payload_grpc.parenthash()};
    auto prev_randao_h256{execution_payload_grpc.prevrandao()};
    auto base_fee_h256{execution_payload_grpc.basefeepergas()};
    auto logs_bloom_h2048{execution_payload_grpc.logsbloom()};
    auto extra_data_string{execution_payload_grpc.extradata()}; // []byte becomes std::string in silkrpc protobuf
    // Convert h2048 to a bloom
    silkworm::Bloom bloom;
    std::memcpy(&bloom[0], bytes_from_H2048(logs_bloom_h2048).data(), 256);
    // Convert transactions in std::string to silkworm::Bytes
    std::vector<silkworm::Bytes> transactions;
    for (const auto& transaction_string : execution_payload_grpc.transactions()) {
        transactions.push_back(silkworm::bytes_of_string(transaction_string));
    }

    // Assembling the execution_payload data structure
    return ExecutionPayload{
        .number = execution_payload_grpc.blocknumber(),
        .timestamp = execution_payload_grpc.timestamp(),
        .gas_limit = execution_payload_grpc.gaslimit(),
        .gas_used = execution_payload_grpc.gasused(),
        .suggested_fee_recipient = address_from_H160(execution_payload_grpc.coinbase()),
        .state_root = bytes32_from_H256(state_root_h256),
        .receipts_root = bytes32_from_H256(receipts_root_h256),
        .parent_hash = bytes32_from_H256(parent_hash_h256),
        .block_hash = bytes32_from_H256(block_hash_h256),
        .prev_randao = bytes32_from_H256(prev_randao_h256),
        .base_fee = uint256_from_H256(base_fee_h256),
        .logs_bloom = bloom,
        .extra_data = silkworm::bytes_of_string(extra_data_string),
        .transactions = transactions
    };
}

types::ExecutionPayload RemoteBackEnd::encode_execution_payload(const ExecutionPayload& execution_payload) {
    types::ExecutionPayload execution_payload_grpc;
    // Numerical parameters
    execution_payload_grpc.set_blocknumber(execution_payload.number);
    execution_payload_grpc.set_timestamp(execution_payload.timestamp);
    execution_payload_grpc.set_gaslimit(execution_payload.gas_limit);
    execution_payload_grpc.set_gasused(execution_payload.gas_used);
    // coinbase
    execution_payload_grpc.set_allocated_coinbase(H160_from_address(execution_payload.suggested_fee_recipient));
    // 32-bytes parameters
    execution_payload_grpc.set_allocated_receiptroot(H256_from_bytes(execution_payload.receipts_root.bytes));
    execution_payload_grpc.set_allocated_stateroot(H256_from_bytes(execution_payload.state_root.bytes));
    execution_payload_grpc.set_allocated_parenthash(H256_from_bytes(execution_payload.parent_hash.bytes));
    execution_payload_grpc.set_allocated_blockhash(H256_from_bytes(execution_payload.block_hash.bytes));
    execution_payload_grpc.set_allocated_prevrandao(H256_from_bytes(execution_payload.prev_randao.bytes));
    execution_payload_grpc.set_allocated_basefeepergas(H256_from_uint256(execution_payload.base_fee));
    // Logs Bloom
    execution_payload_grpc.set_allocated_logsbloom(H2048_from_bytes(&execution_payload.logs_bloom[0]));
    // String-like parameters
    for (auto transaction_bytes : execution_payload.transactions) {
        execution_payload_grpc.add_transactions(std::string(transaction_bytes.begin(), transaction_bytes.end()));
    }
    execution_payload_grpc.set_extradata(std::string(execution_payload.extra_data.begin(), execution_payload.extra_data.end()));
    return execution_payload_grpc;
}

remote::EngineForkChoiceState* RemoteBackEnd::encode_forkchoice_state(const ForkChoiceState& forkchoice_state) {
    remote::EngineForkChoiceState *forkchoice_state_grpc = new remote::EngineForkChoiceState();
    // 32-bytes parameters
    forkchoice_state_grpc->set_allocated_headblockhash(H256_from_bytes(forkchoice_state.head_block_hash.bytes));
    forkchoice_state_grpc->set_allocated_safeblockhash(H256_from_bytes(forkchoice_state.safe_block_hash.bytes));
    forkchoice_state_grpc->set_allocated_finalizedblockhash(H256_from_bytes(forkchoice_state.finalized_block_hash.bytes));
    return forkchoice_state_grpc;
}

remote::EnginePayloadAttributes* RemoteBackEnd::encode_payload_attributes(const PayloadAttributes& payload_attributes) {
    remote::EnginePayloadAttributes *payload_attributes_grpc = new remote::EnginePayloadAttributes();
    // Numerical parameters
    payload_attributes_grpc->set_timestamp(payload_attributes.timestamp);
    //32-bytes parameters
    payload_attributes_grpc->set_allocated_prevrandao(H256_from_bytes(payload_attributes.prev_randao.bytes));
    // Address parameters
    payload_attributes_grpc->set_allocated_suggestedfeerecipient(H160_from_address(payload_attributes.suggested_fee_recipient));

    return payload_attributes_grpc;
}

remote::EngineForkChoiceUpdatedRequest RemoteBackEnd::encode_forkchoice_updated_request(const ForkChoiceUpdatedRequest& forkchoice_updated_request) {
    remote::EngineForkChoiceUpdatedRequest forkchoice_updated_request_grpc;
    remote::EngineForkChoiceState *forkchoice_state_grpc = RemoteBackEnd::encode_forkchoice_state(forkchoice_updated_request.fork_choice_state);

    forkchoice_updated_request_grpc.set_allocated_forkchoicestate(forkchoice_state_grpc);
    if (forkchoice_updated_request.payload_attributes != std::nullopt) {
        remote::EnginePayloadAttributes *payload_attributes_grpc =
            RemoteBackEnd::encode_payload_attributes(forkchoice_updated_request.payload_attributes.value());
        forkchoice_updated_request_grpc.set_allocated_payloadattributes(payload_attributes_grpc);
    }
    return forkchoice_updated_request_grpc;
}

PayloadStatus RemoteBackEnd::decode_payload_status(const remote::EnginePayloadStatus& payload_status_grpc) {
    PayloadStatus payload_status;
    payload_status.status = decode_status_message(payload_status_grpc.status());
    // Set LatestValidHash (if there is one)
    if (payload_status_grpc.has_latestvalidhash()) {
        payload_status.latest_valid_hash = bytes32_from_H256(payload_status_grpc.latestvalidhash());
    }
    // Set ValidationError (if there is one)
    const auto validation_error{payload_status_grpc.validationerror()};
    if (validation_error != "") {
        payload_status.validation_error = validation_error;
    }
    return payload_status;
}

std::string RemoteBackEnd::decode_status_message(const remote::EngineStatus& status) {
    switch (status) {
        case remote::EngineStatus::VALID:
            return "VALID";
        case remote::EngineStatus::SYNCING:
            return "SYNCING";
        case remote::EngineStatus::ACCEPTED:
            return "ACCEPTED";
        case remote::EngineStatus::INVALID_BLOCK_HASH:
            return "INVALID_BLOCK_HASH";
        default:
            return "INVALID";
    }
}

} // namespace silkrpc::ethbackend
