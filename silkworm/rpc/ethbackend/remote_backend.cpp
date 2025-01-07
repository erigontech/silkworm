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

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/infra/common/clock_time.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/client/call.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc::ethbackend {

namespace proto = ::remote;
using Stub = proto::ETHBACKEND::StubInterface;

RemoteBackEnd::RemoteBackEnd(
    boost::asio::io_context& ioc,
    const std::shared_ptr<grpc::Channel>& channel,
    agrpc::GrpcContext& grpc_context)
    : RemoteBackEnd(ioc.get_executor(), ::remote::ETHBACKEND::NewStub(channel), grpc_context) {}

RemoteBackEnd::RemoteBackEnd(boost::asio::io_context::executor_type executor,
                             std::unique_ptr<Stub> stub,
                             agrpc::GrpcContext& grpc_context)
    : executor_(std::move(executor)), stub_(std::move(stub)), grpc_context_(grpc_context) {}

Task<evmc::address> RemoteBackEnd::etherbase() {
    const auto start_time = clock_time::now();
    const proto::EtherbaseRequest request;
    const auto reply = co_await rpc::unary_rpc(&Stub::AsyncEtherbase, *stub_, request, grpc_context_);
    evmc::address evmc_address;
    if (reply.has_address()) {
        const auto& h160_address = reply.address();
        evmc_address = address_from_h160(h160_address);
    }
    SILK_TRACE << "RemoteBackEnd::etherbase address=" << evmc_address << " t=" << clock_time::since(start_time);
    co_return evmc_address;
}

Task<uint64_t> RemoteBackEnd::protocol_version() {
    const auto start_time = clock_time::now();
    const proto::ProtocolVersionRequest request;
    const auto reply = co_await rpc::unary_rpc(&Stub::AsyncProtocolVersion, *stub_, request, grpc_context_);
    const auto pv = reply.id();
    SILK_TRACE << "RemoteBackEnd::protocol_version version=" << pv << " t=" << clock_time::since(start_time);
    co_return pv;
}

Task<BlockNum> RemoteBackEnd::net_version() {
    const auto start_time = clock_time::now();
    const proto::NetVersionRequest request;
    const auto reply = co_await rpc::unary_rpc(&Stub::AsyncNetVersion, *stub_, request, grpc_context_);
    const auto nv = reply.id();
    SILK_TRACE << "RemoteBackEnd::net_version version=" << nv << " t=" << clock_time::since(start_time);
    co_return nv;
}

Task<std::string> RemoteBackEnd::client_version() {
    const auto start_time = clock_time::now();
    const proto::ClientVersionRequest request;
    const auto reply = co_await rpc::unary_rpc(&Stub::AsyncClientVersion, *stub_, request, grpc_context_);
    const auto& cv = reply.node_name();
    SILK_TRACE << "RemoteBackEnd::client_version version=" << cv << " t=" << clock_time::since(start_time);
    co_return cv;
}

Task<uint64_t> RemoteBackEnd::net_peer_count() {
    const auto start_time = clock_time::now();
    const proto::NetPeerCountRequest request;
    const auto reply = co_await rpc::unary_rpc(&Stub::AsyncNetPeerCount, *stub_, request, grpc_context_);
    const auto count = reply.count();
    SILK_TRACE << "RemoteBackEnd::net_peer_count count=" << count << " t=" << clock_time::since(start_time);
    co_return count;
}

Task<NodeInfos> RemoteBackEnd::engine_node_info() {
    NodeInfos node_info_list;
    const auto start_time = clock_time::now();
    const proto::NodesInfoRequest request;
    const auto reply = co_await rpc::unary_rpc(&Stub::AsyncNodeInfo, *stub_, request, grpc_context_);
    for (int i = 0; i < reply.nodes_info_size(); ++i) {
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

Task<PeerInfos> RemoteBackEnd::peers() {
    const auto start_time = clock_time::now();
    const ::google::protobuf::Empty request;
    const auto reply = co_await rpc::unary_rpc(&Stub::AsyncPeers, *stub_, request, grpc_context_);
    PeerInfos peer_infos;
    peer_infos.reserve(static_cast<size_t>(reply.peers_size()));
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

Task<bool> RemoteBackEnd::get_block(BlockNum block_num, const HashAsSpan& hash, bool read_senders, silkworm::Block& block) {
    const auto start_time = clock_time::now();
    ::remote::BlockRequest request;
    request.set_block_height(block_num);
    request.set_allocated_block_hash(h256_from_bytes(hash).release());
    const auto reply = co_await rpc::unary_rpc(&Stub::AsyncBlock, *stub_, request, grpc_context_);
    ByteView block_rlp{string_view_to_byte_view(reply.block_rlp())};
    if (const auto decode_result{rlp::decode(block_rlp, block)}; !decode_result) {
        co_return false;
    }
    if (read_senders) {
        ByteView senders{string_view_to_byte_view(reply.senders())};
        if (senders.size() % kAddressLength == 0 && senders.size() / kAddressLength == block.transactions.size()) {
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

Task<std::optional<BlockNum>> RemoteBackEnd::get_block_num_from_txn_hash(const HashAsSpan& hash) {
    const auto start_time = clock_time::now();
    ::remote::TxnLookupRequest request;
    request.set_allocated_txn_hash(h256_from_bytes(hash).release());
    const auto reply = co_await rpc::unary_rpc(&Stub::AsyncTxnLookup, *stub_, request, grpc_context_);
    if (reply.block_number() == 0) {
        co_return std::nullopt;
    }
    auto block_num = reply.block_number();
    SILK_TRACE << "RemoteBackEnd::get_block_num_from_txn_hash block_num=" << block_num << " t=" << clock_time::since(start_time);
    co_return block_num;
}

Task<std::optional<BlockNum>> RemoteBackEnd::get_block_num_from_hash(const HashAsSpan& hash) {
    const auto start_time = clock_time::now();
    ::remote::HeaderNumberRequest request;
    request.set_allocated_hash(h256_from_bytes(hash).release());
    const auto reply = co_await rpc::unary_rpc(&Stub::AsyncHeaderNumber, *stub_, request, grpc_context_);
    if (!reply.has_number()) {
        co_return std::nullopt;
    }
    auto block_num = reply.number();
    SILK_TRACE << "RemoteBackEnd::get_block_num_from_hash block_num=" << block_num << " t=" << clock_time::since(start_time);
    co_return block_num;
}

Task<std::optional<evmc::bytes32>> RemoteBackEnd::get_block_hash_from_block_num(BlockNum block_num) {
    const auto start_time = clock_time::now();
    ::remote::CanonicalHashRequest request;
    request.set_block_number(block_num);
    const auto reply = co_await rpc::unary_rpc(&Stub::AsyncCanonicalHash, *stub_, request, grpc_context_);
    evmc::bytes32 hash;
    if (reply.has_hash() == 0) {
        co_return std::nullopt;
    }
    span_from_h256(reply.hash(), hash.bytes);
    SILK_TRACE << "RemoteBackEnd::get_block_hash_from_block_num block_num="
               << " t=" << clock_time::since(start_time);
    co_return hash;
}

Task<std::optional<Bytes>> RemoteBackEnd::canonical_body_for_storage(BlockNum block_num) {
    const auto start_time = clock_time::now();
    ::remote::CanonicalBodyForStorageRequest request;
    request.set_blocknumber(block_num);
    const auto reply = co_await rpc::unary_rpc(&Stub::AsyncCanonicalBodyForStorage, *stub_, request, grpc_context_);
    SILK_TRACE << "RemoteBackEnd::canonical_body_for_storage block_num=" << block_num
               << " t=" << clock_time::since(start_time);
    if (reply.body().empty()) {
        co_return std::nullopt;
    }
    co_return string_to_bytes(reply.body());
}

std::vector<Bytes> RemoteBackEnd::decode(const ::google::protobuf::RepeatedPtrField<std::string>& grpc_txs) {
    // Convert encoded transactions from std::string to Bytes
    std::vector<Bytes> encoded_transactions;
    encoded_transactions.reserve(static_cast<size_t>(grpc_txs.size()));
    for (const auto& grpc_tx_string : grpc_txs) {
        encoded_transactions.push_back(string_to_bytes(grpc_tx_string));
    }
    return encoded_transactions;
}

std::vector<Withdrawal> RemoteBackEnd::decode(const ::google::protobuf::RepeatedPtrField<::types::Withdrawal>& grpc_withdrawals) {
    std::vector<Withdrawal> withdrawals;
    withdrawals.reserve(static_cast<size_t>(grpc_withdrawals.size()));
    for (auto& grpc_withdrawal : grpc_withdrawals) {
        Withdrawal w{grpc_withdrawal.index(),
                     grpc_withdrawal.validator_index(),
                     address_from_h160(grpc_withdrawal.address()),
                     grpc_withdrawal.amount()};
        withdrawals.emplace_back(w);
    }
    return withdrawals;
}

}  // namespace silkworm::rpc::ethbackend
