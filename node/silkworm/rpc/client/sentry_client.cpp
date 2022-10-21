/*
   Copyright 2022 The Silkworm Authors

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

#include "sentry_client.hpp"

#include <chrono>

#include <agrpc/asio_grpc.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/conversion.hpp>
#include <silkworm/rpc/util.hpp>
#include <utility>

namespace silkworm::rpc {

using SetStatusResult = RemoteSentryClient::SetStatusResult;
using PeerCountResult = RemoteSentryClient::PeerCountResult;
using NodeInfoResult = RemoteSentryClient::NodeInfoResult;

RemoteSentryClient::RemoteSentryClient(agrpc::GrpcContext& grpc_context, const std::shared_ptr<grpc::Channel>& channel,
                                       std::string address_uri)
    : grpc_context_(grpc_context), stub_(sentry::Sentry::NewStub(channel)), address_uri_(std::move(address_uri)) {}

boost::asio::awaitable<PeerCountResult> RemoteSentryClient::peer_count() {
    /*SILK_TRACE << "RemoteSentryClient::peer_count START address: " << address_uri_;
    grpc::ClientContext client_context;
    sentry::PeerCountRequest request;
    std::unique_ptr<grpc::ClientAsyncResponseReader<sentry::PeerCountReply>> reader =
        agrpc::request(&sentry::Sentry::Stub::AsyncPeerCount, stub_, client_context, request, grpc_context_);

    SILK_DEBUG << "RemoteSentryClient::peer_count going to finish address: " << address_uri_;
    sentry::PeerCountReply reply;
    grpc::Status status;
    bool finish_ok = co_await agrpc::finish(reader, reply, status, boost::asio::bind_executor(grpc_context_, boost::asio::use_awaitable));
    if (!finish_ok) {
        const auto error_msg = "PeerCount RPC failed to address: " + address_uri_;
        SILK_WARN << "RemoteSentryClient::peer_count " << error_msg;
        throw std::runtime_error{error_msg};
    }
    SILK_TRACE << "RemoteSentryClient::peer_count END address: " << address_uri_ << " " << status;
    co_return PeerCountResult{status, reply};*/
    SILK_TRACE << "RemoteSentryClient::peer_count START address: " << address_uri_;
    sentry::PeerCountRequest request;
    sentry::PeerCountReply reply;
    const auto status = co_await unary_rpc(&sentry::Sentry::Stub::AsyncPeerCount, stub_, request, reply, grpc_context_);
    SILK_TRACE << "RemoteSentryClient::peer_count END address: " << address_uri_ << " " << status;
    co_return PeerCountResult{status, reply};
}

boost::asio::awaitable<NodeInfoResult> RemoteSentryClient::node_info() {
    SILK_TRACE << "RemoteSentryClient::node_info START address: " << address_uri_;
    grpc::ClientContext client_context;
    google::protobuf::Empty request;
    std::unique_ptr<grpc::ClientAsyncResponseReader<types::NodeInfoReply>> reader =
        agrpc::request(&sentry::Sentry::Stub::AsyncNodeInfo, stub_, client_context, request, grpc_context_);

    SILK_DEBUG << "RemoteSentryClient::node_info going to finish address: " << address_uri_;
    types::NodeInfoReply reply;
    grpc::Status status;
    bool finish_ok = co_await agrpc::finish(reader, reply, status, boost::asio::bind_executor(grpc_context_, boost::asio::use_awaitable));
    if (!finish_ok) {
        const auto error_msg = "NodeInfo RPC failed to address: " + address_uri_;
        SILK_WARN << "RemoteSentryClient::node_info " << error_msg;
        throw std::runtime_error{error_msg};
    }
    SILK_TRACE << "RemoteSentryClient::node_info END address: " << address_uri_ << " " << status;
    co_return NodeInfoResult{status, reply};
}

boost::asio::awaitable<SetStatusResult> RemoteSentryClient::set_status(SentryStatus sentry_status) {
    SILK_TRACE << "RemoteSentryClient::set_status START address: " << address_uri_;
    grpc::ClientContext client_context;
    sentry::StatusData request;
    request.set_network_id(sentry_status.network_id);
    request.set_allocated_total_difficulty(rpc::H256_from_uint256(sentry_status.head_td).release());
    request.set_allocated_best_hash(rpc::H256_from_bytes32(sentry_status.head_hash).release());
    auto* forks = new sentry::Forks{};
    forks->set_allocated_genesis(rpc::H256_from_bytes32(sentry_status.genesis_hash).release());
    for (uint64_t block : sentry_status.forks) {
        forks->add_forks(block);
    }
    request.set_allocated_fork_data(forks);

    std::unique_ptr<grpc::ClientAsyncResponseReader<sentry::SetStatusReply>> reader =
        agrpc::request(&sentry::Sentry::Stub::AsyncSetStatus, stub_, client_context, request, grpc_context_);

    SILK_DEBUG << "RemoteSentryClient::set_status going to finish address: " << address_uri_;
    sentry::SetStatusReply reply;
    grpc::Status status;
    bool finish_ok = co_await agrpc::finish(reader, reply, status, boost::asio::bind_executor(grpc_context_, boost::asio::use_awaitable));
    if (!finish_ok) {
        throw std::runtime_error{"finish failed"};
    }
    SILK_TRACE << "RemoteSentryClient::set_status END address: " << address_uri_ << " " << status;
    co_return SetStatusResult{status, reply};
}

std::unique_ptr<SentryClient> RemoteSentryClientFactory::make_sentry_client(const std::string& address_uri) {
    auto channel = grpc::CreateChannel(address_uri, grpc::InsecureChannelCredentials());
    return std::make_unique<RemoteSentryClient>(grpc_context_, channel, address_uri);
}

}  // namespace silkworm::rpc
