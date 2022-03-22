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

#include <silkworm/rpc/util.hpp>

namespace silkworm::rpc {

UnaryStats AsyncCall::unary_stats_;

AsyncPeerCountCall::AsyncPeerCountCall(grpc::CompletionQueue* queue, CompletionFunc completion_handler, SentryStubPtr& stub)
: AsyncUnaryCall(queue, completion_handler, stub) {
}

bool AsyncPeerCountCall::proceed(bool ok) {
    SILK_DEBUG << "AsyncPeerCountCall::proceed ok: " << ok << " status: " << status_;
    ++unary_stats_.completed_count;
    if (ok && status_.ok()) {
        SILK_INFO << "PeerCount reply: count=" << reply_.count();
        ++unary_stats_.ok_count;
    } else {
        SILK_INFO << "PeerCount " << status_;
        ++unary_stats_.ko_count;
    }
    return true;
}

AsyncNodeInfoCall::AsyncNodeInfoCall(grpc::CompletionQueue* queue, CompletionFunc completion_handler, SentryStubPtr& stub)
: AsyncUnaryCall(queue, completion_handler, stub) {
}

bool AsyncNodeInfoCall::proceed(bool ok) {
    SILK_DEBUG << "AsyncNodeInfoCall::proceed ok: " << ok << " status: " << status_;
    ++unary_stats_.completed_count;
    if (ok && status_.ok()) {
        SILK_INFO << "NodeInfo reply: id=" << reply_.id() << " name=" << reply_.name() << " enode=" << reply_.enode();
        ++unary_stats_.ok_count;
    } else {
        SILK_INFO << "NodeInfo " << status_;
        ++unary_stats_.ko_count;
    }
    return true;
}

RemoteSentryClient::RemoteSentryClient(grpc::CompletionQueue* queue, std::shared_ptr<grpc::Channel> channel)
: queue_(queue), stub_(sentry::Sentry::NewStub(channel)) {
}

void RemoteSentryClient::peer_count(PeerCountCallback callback) {
    const auto rpc = new AsyncPeerCountCall(queue_, [this, callback](auto* call) {
        callback(call->status(), call->reply());
        //remove_rpc(call);
    }, stub_);
    add_rpc(rpc);
    rpc->start(sentry::PeerCountRequest{});
}

void RemoteSentryClient::node_info(NodeInfoCallback callback) {
    const auto rpc = new AsyncNodeInfoCall(queue_, [this, callback](auto* call) {
        callback(call->status(), call->reply());
        //remove_rpc(call);
    }, stub_);
    add_rpc(rpc);
    rpc->start(google::protobuf::Empty{});
}

std::unique_ptr<SentryClient> RemoteSentryClientFactory::make_sentry_client(const std::string& address_uri) {
    auto channel = grpc::CreateChannel(address_uri, grpc::InsecureChannelCredentials());
    return std::make_unique<RemoteSentryClient>(queue_, channel);
}

} // namespace silkworm::rpc
