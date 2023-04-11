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

#include "backend_calls.hpp"

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/rpc/client/call.hpp>
#include <silkworm/infra/rpc/common/conversion.hpp>
#include <silkworm/infra/rpc/common/util.hpp>
#include <silkworm/interfaces/types/types.pb.h>

namespace silkworm::rpc {

using boost::asio::awaitable;

remote::EtherbaseReply EtherbaseCall::response_;

void EtherbaseCall::fill_predefined_reply(const EthereumBackEnd& backend) {
    const auto etherbase = backend.etherbase();
    if (etherbase.has_value()) {
        const auto h160 = H160_from_address(etherbase.value()).release();
        EtherbaseCall::response_.set_allocated_address(h160);
    }
}

awaitable<void> EtherbaseCall::operator()(const EthereumBackEnd& /*backend*/) {
    SILK_TRACE << "EtherbaseCall START";
    if (response_.has_address()) {
        co_await agrpc::finish(responder_, response_, grpc::Status::OK);
        SILK_TRACE << "EtherbaseCall END etherbase: " << to_hex(address_from_H160(response_.address()));
    } else {
        const grpc::Status error{grpc::StatusCode::INTERNAL, "etherbase must be explicitly specified"};
        co_await agrpc::finish_with_error(responder_, error);
        SILK_TRACE << "EtherbaseCall END error: " << error;
    }
}

remote::NetVersionReply NetVersionCall::response_;

void NetVersionCall::fill_predefined_reply(const EthereumBackEnd& backend) {
    if (backend.chain_id()) {
        NetVersionCall::response_.set_id(*backend.chain_id());
    } else {
        NetVersionCall::response_.set_id(0);  // unused chain ID
    }
}

awaitable<void> NetVersionCall::operator()(const EthereumBackEnd& /*backend*/) {
    SILK_TRACE << "NetVersionCall START";
    co_await agrpc::finish(responder_, response_, grpc::Status::OK);
    SILK_TRACE << "NetVersionCall END chain_id: " << response_.id();
}

std::set<SentryClient*> NetPeerCountCall::sentries_;

void NetPeerCountCall::add_sentry(SentryClient* sentry) {
    NetPeerCountCall::sentries_.insert(sentry);
}

void NetPeerCountCall::remove_sentry(SentryClient* sentry) {
    NetPeerCountCall::sentries_.erase(sentry);
}

awaitable<void> NetPeerCountCall::operator()(const EthereumBackEnd& backend) {
    SILK_TRACE << "NetPeerCountCall START [#sentries: " << sentries_.size() << "]";

    // This sequential implementation is far from ideal when num sentries > 0 because request latencies sum up
    // We need when_all algorithm for coroutines or make_parallel_group (see *convoluted* parallel_sort in asio examples)
    uint64_t total_peer_count{0};
    grpc::Status result_status{grpc::Status::OK};
    for (const auto& sentry : sentries_) {
        try {
            const auto reply = co_await sentry->peer_count();
            const uint64_t count = reply.count();
            total_peer_count += count;
            SILK_DEBUG << "Reply OK peer count: partial=" << count << " total=" << total_peer_count;
        } catch (const GrpcStatusError& status_error) {
            result_status = status_error.status();
            SILK_DEBUG << "Reply KO result: " << result_status;
        }
    }

    if (result_status.ok()) {
        remote::NetPeerCountReply response;
        response.set_count(total_peer_count);
        co_await agrpc::finish(responder_, response, grpc::Status::OK);
        SILK_TRACE << "NetPeerCountCall END count: " << total_peer_count;
    } else {
        co_await agrpc::finish_with_error(responder_, result_status);
        SILK_TRACE << "NetPeerCountCall END error: " << result_status;
    }
}

types::VersionReply BackEndVersionCall::response_;

void BackEndVersionCall::fill_predefined_reply() {
    BackEndVersionCall::response_.set_major(std::get<0>(kEthBackEndApiVersion));
    BackEndVersionCall::response_.set_minor(std::get<1>(kEthBackEndApiVersion));
    BackEndVersionCall::response_.set_patch(std::get<2>(kEthBackEndApiVersion));
}

awaitable<void> BackEndVersionCall::operator()(const EthereumBackEnd& /*backend*/) {
    SILK_TRACE << "BackEndVersionCall START";
    co_await agrpc::finish(responder_, response_, grpc::Status::OK);
    SILK_TRACE << "BackEndVersionCall END version: " << response_.major() << "." << response_.minor() << "." << response_.patch();
}

remote::ProtocolVersionReply ProtocolVersionCall::response_;

void ProtocolVersionCall::fill_predefined_reply() {
    ProtocolVersionCall::response_.set_id(kEthDevp2pProtocolVersion);
}

awaitable<void> ProtocolVersionCall::operator()(const EthereumBackEnd& /*backend*/) {
    SILK_TRACE << "ProtocolVersionCall START";
    co_await agrpc::finish(responder_, response_, grpc::Status::OK);
    SILK_TRACE << "ProtocolVersionCall END id: " << response_.id();
}

remote::ClientVersionReply ClientVersionCall::response_;

void ClientVersionCall::fill_predefined_reply(const EthereumBackEnd& backend) {
    ClientVersionCall::response_.set_nodename(backend.node_name());
}

awaitable<void> ClientVersionCall::operator()(const EthereumBackEnd& /*backend*/) {
    SILK_TRACE << "ClientVersionCall START";
    co_await agrpc::finish(responder_, response_, grpc::Status::OK);
    SILK_TRACE << "ClientVersionCall END node name: " << response_.nodename();
}

awaitable<void> SubscribeCall::operator()(const EthereumBackEnd& /*backend*/) {
    SILK_TRACE << "SubscribeCall START type: " << request_.type();

    // TODO(canepat): remove this example and fill the correct stream responses
    remote::SubscribeReply response1;
    response1.set_type(remote::Event::PENDING_BLOCK);
    response1.set_data("001122");
    co_await agrpc::write(responder_, response1);
    remote::SubscribeReply response2;
    response2.set_type(remote::Event::PENDING_LOGS);
    response2.set_data("334455");
    co_await agrpc::write_and_finish(responder_, response2, grpc::WriteOptions{}, grpc::Status::OK);

    SILK_TRACE << "SubscribeCall END";
}

std::set<SentryClient*> NodeInfoCall::sentries_;

void NodeInfoCall::add_sentry(SentryClient* sentry) {
    NodeInfoCall::sentries_.insert(sentry);
}

void NodeInfoCall::remove_sentry(SentryClient* sentry) {
    NodeInfoCall::sentries_.erase(sentry);
}

awaitable<void> NodeInfoCall::operator()(const EthereumBackEnd& backend) {
    SILK_TRACE << "NodeInfoCall START limit: " << request_.limit() << " [#sentries: " << sentries_.size() << "]";

    // This sequential implementation is far from ideal when num sentries > 0 because request latencies sum up
    // We need when_all algorithm for coroutines or make_parallel_group (see *convoluted* parallel_sort in asio examples)
    remote::NodesInfoReply response;
    grpc::Status result_status{grpc::Status::OK};
    for (const auto& sentry : sentries_) {
        try {
            const auto reply = co_await sentry->node_info();
            types::NodeInfoReply* nodes_info = response.add_nodesinfo();
            *nodes_info = reply;
            SILK_DEBUG << "Reply OK node info: name=" << reply.name();
        } catch (const GrpcStatusError& status_error) {
            result_status = status_error.status();
            SILK_DEBUG << "Reply KO result: " << result_status;
        }
    }

    if (result_status.ok()) {
        co_await agrpc::finish(responder_, response, grpc::Status::OK);
        SILK_TRACE << "NodeInfoCall END #nodes: " << response.nodesinfo_size();
    } else {
        co_await agrpc::finish_with_error(responder_, result_status);
        SILK_TRACE << "NodeInfoCall END error: " << result_status;
    }
}

}  // namespace silkworm::rpc
