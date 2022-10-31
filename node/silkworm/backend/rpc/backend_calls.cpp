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

#include <silkworm/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <types/types.pb.h>

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/common/conversion.hpp>
#include <silkworm/rpc/common/util.hpp>

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

awaitable<void> EtherbaseCall::operator()() {
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

awaitable<void> NetVersionCall::operator()() {
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

awaitable<void> NetPeerCountCall::operator()() {
    SILK_TRACE << "NetPeerCountCall START [#sentries: " << sentries_.size() << "]";

    // This sequential implementation is far from ideal when num sentries > 0 because request latencies sum up
    // We need when_all algorithm for coroutines or make_parallel_group (see *convoluted* parallel_sort in asio examples)
    uint64_t total_peer_count{0};
    grpc::Status result_status{grpc::Status::OK};
    for (const auto& sentry : sentries_) {
        const auto [status, reply] = co_await sentry->peer_count();
        if (status.ok()) {
            const uint64_t count = reply.count();
            total_peer_count += count;
            SILK_DEBUG << "Reply OK peer count: partial=" << count << " total=" << total_peer_count;
        } else {
            result_status = status;
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

awaitable<void> BackEndVersionCall::operator()() {
    SILK_TRACE << "BackEndVersionCall START";
    co_await agrpc::finish(responder_, response_, grpc::Status::OK);
    SILK_TRACE << "BackEndVersionCall END version: " << response_.major() << "." << response_.minor() << "." << response_.patch();
}

remote::ProtocolVersionReply ProtocolVersionCall::response_;

void ProtocolVersionCall::fill_predefined_reply() {
    ProtocolVersionCall::response_.set_id(kEthDevp2pProtocolVersion);
}

awaitable<void> ProtocolVersionCall::operator()() {
    SILK_TRACE << "ProtocolVersionCall START";
    co_await agrpc::finish(responder_, response_, grpc::Status::OK);
    SILK_TRACE << "ProtocolVersionCall END id: " << response_.id();
}

remote::ClientVersionReply ClientVersionCall::response_;

void ClientVersionCall::fill_predefined_reply(const EthereumBackEnd& backend) {
    ClientVersionCall::response_.set_nodename(backend.node_name());
}

awaitable<void> ClientVersionCall::operator()() {
    SILK_TRACE << "ClientVersionCall START";
    co_await agrpc::finish(responder_, response_, grpc::Status::OK);
    SILK_TRACE << "ClientVersionCall END node name: " << response_.nodename();
}

awaitable<void> SubscribeCall::operator()() {
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

awaitable<void> NodeInfoCall::operator()() {
    SILK_TRACE << "NodeInfoCall START limit: " << request_.limit() << " [#sentries: " << sentries_.size() << "]";

    // This sequential implementation is far from ideal when num sentries > 0 because request latencies sum up
    // We need when_all algorithm for coroutines or make_parallel_group (see *convoluted* parallel_sort in asio examples)
    remote::NodesInfoReply response;
    grpc::Status result_status{grpc::Status::OK};
    for (const auto& sentry : sentries_) {
        const auto [status, reply] = co_await sentry->node_info();
        if (status.ok()) {
            types::NodeInfoReply* nodes_info = response.add_nodesinfo();
            *nodes_info = reply;
            SILK_DEBUG << "Reply OK node info: name=" << reply.name();
        } else {
            result_status = status;
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

BackEndService::BackEndService(const EthereumBackEnd& backend) {
    EtherbaseCall::fill_predefined_reply(backend);
    NetVersionCall::fill_predefined_reply(backend);
    BackEndVersionCall::fill_predefined_reply();
    ProtocolVersionCall::fill_predefined_reply();
    ClientVersionCall::fill_predefined_reply(backend);
}

void BackEndService::register_backend_request_calls(const ServerContext& context, remote::ETHBACKEND::AsyncService* service) {
    SILK_DEBUG << "BackEndService::register_backend_request_calls START";
    const auto grpc_context = context.server_grpc_context();
    // Register one requested call repeatedly for each RPC: asio-grpc will take care of re-registration on any incoming call
    request_repeatedly(*grpc_context, service, &remote::ETHBACKEND::AsyncService::RequestEtherbase,
                       [](auto&&... args) -> awaitable<void> {
                           co_await EtherbaseCall{std::forward<decltype(args)>(args)...}();
                       });
    request_repeatedly(*grpc_context, service, &remote::ETHBACKEND::AsyncService::RequestNetVersion,
                       [](auto&&... args) -> awaitable<void> {
                           co_await NetVersionCall{std::forward<decltype(args)>(args)...}();
                       });
    request_repeatedly(*grpc_context, service, &remote::ETHBACKEND::AsyncService::RequestNetPeerCount,
                       [](auto&&... args) -> awaitable<void> {
                           co_await NetPeerCountCall{std::forward<decltype(args)>(args)...}();
                       });
    request_repeatedly(*grpc_context, service, &remote::ETHBACKEND::AsyncService::RequestVersion,
                       [](auto&&... args) -> awaitable<void> {
                           co_await BackEndVersionCall{std::forward<decltype(args)>(args)...}();
                       });
    request_repeatedly(*grpc_context, service, &remote::ETHBACKEND::AsyncService::RequestProtocolVersion,
                       [](auto&&... args) -> awaitable<void> {
                           co_await ProtocolVersionCall{std::forward<decltype(args)>(args)...}();
                       });
    request_repeatedly(*grpc_context, service, &remote::ETHBACKEND::AsyncService::RequestClientVersion,
                       [](auto&&... args) -> awaitable<void> {
                           co_await ClientVersionCall{std::forward<decltype(args)>(args)...}();
                       });
    request_repeatedly(*grpc_context, service, &remote::ETHBACKEND::AsyncService::RequestSubscribe,
                       [](auto&&... args) -> awaitable<void> {
                           co_await SubscribeCall{std::forward<decltype(args)>(args)...}();
                       });
    request_repeatedly(*grpc_context, service, &remote::ETHBACKEND::AsyncService::RequestNodeInfo,
                       [](auto&&... args) -> awaitable<void> {
                           co_await NodeInfoCall{std::forward<decltype(args)>(args)...}();
                       });
    SILK_DEBUG << "BackEndService::register_backend_request_calls END";
}

void BackEndService::add_sentry(std::unique_ptr<SentryClient>&& sentry) {
    NetPeerCountCall::add_sentry(sentry.get());
    NodeInfoCall::add_sentry(sentry.get());
    sentries_.push_back(std::move(sentry));
}

BackEndService::~BackEndService() {
    for (const auto& sentry : sentries_) {
        NetPeerCountCall::remove_sentry(sentry.get());
        NodeInfoCall::remove_sentry(sentry.get());
    }
}

}  // namespace silkworm::rpc
