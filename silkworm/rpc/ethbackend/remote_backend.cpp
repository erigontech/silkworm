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
#include <silkworm/db/kv/api/util.hpp>
#include <silkworm/infra/common/clock_time.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/client/unary_rpc.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>
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

}  // namespace silkworm::rpc::ethbackend
