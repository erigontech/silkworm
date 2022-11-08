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
#include <utility>  // for std::exchange in Boost 1.78, fixed in Boost 1.79

#include <agrpc/asio_grpc.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/common/conversion.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc {

using SetStatusResult = RemoteSentryClient::SetStatusResult;
using PeerCountResult = RemoteSentryClient::PeerCountResult;
using NodeInfoResult = RemoteSentryClient::NodeInfoResult;

RemoteSentryClient::RemoteSentryClient(agrpc::GrpcContext& grpc_context, const std::shared_ptr<grpc::Channel>& channel,
                                       std::string address_uri)
    : grpc_context_(grpc_context), stub_(sentry::Sentry::NewStub(channel)), address_uri_(std::move(address_uri)) {}

boost::asio::awaitable<PeerCountResult> RemoteSentryClient::peer_count() {
    SILK_TRACE << "RemoteSentryClient::peer_count START address: " << address_uri_;
    sentry::PeerCountRequest request;
    sentry::PeerCountReply reply;
    const auto status = co_await unary_rpc(&sentry::Sentry::Stub::AsyncPeerCount, stub_, request, reply, grpc_context_);
    SILK_TRACE << "RemoteSentryClient::peer_count END address: " << address_uri_ << " " << status;
    co_return PeerCountResult{status, reply};
}

boost::asio::awaitable<NodeInfoResult> RemoteSentryClient::node_info() {
    SILK_TRACE << "RemoteSentryClient::node_info START address: " << address_uri_;
    google::protobuf::Empty request;
    types::NodeInfoReply reply;
    const auto status = co_await unary_rpc(&sentry::Sentry::Stub::AsyncNodeInfo, stub_, request, reply, grpc_context_);
    SILK_TRACE << "RemoteSentryClient::node_info END address: " << address_uri_ << " " << status;
    co_return NodeInfoResult{status, reply};
}

boost::asio::awaitable<SetStatusResult> RemoteSentryClient::set_status(SentryStatus sentry_status) {
    SILK_TRACE << "RemoteSentryClient::set_status START address: " << address_uri_;
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
    sentry::SetStatusReply reply;
    const auto status = co_await unary_rpc(&sentry::Sentry::Stub::AsyncSetStatus, stub_, request, reply, grpc_context_);
    SILK_TRACE << "RemoteSentryClient::set_status END address: " << address_uri_ << " " << status;
    co_return SetStatusResult{status, reply};
}

std::unique_ptr<SentryClient> RemoteSentryClientFactory::make_sentry_client(const std::string& address_uri) {
    auto channel = grpc::CreateChannel(address_uri, grpc::InsecureChannelCredentials());
    return std::make_unique<RemoteSentryClient>(grpc_context_, channel, address_uri);
}

}  // namespace silkworm::rpc
