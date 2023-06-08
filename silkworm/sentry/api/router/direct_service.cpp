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

#include "direct_service.hpp"

#include <memory>

#include <boost/asio/this_coro.hpp>
#include <gsl/util>

#include <silkworm/infra/concurrency/awaitable_future.hpp>
#include <silkworm/sentry/api/api_common/peer_filter.hpp>

#include "messages_call.hpp"
#include "peer_call.hpp"
#include "peer_events_call.hpp"
#include "send_message_call.hpp"

namespace silkworm::sentry::api::router {

using namespace boost::asio;

Task<void> DirectService::set_status(eth::StatusData status_data) {
    status_data.message.version = router_.eth_version;
    co_await router_.status_channel.send(std::move(status_data));
}

Task<uint8_t> DirectService::handshake() {
    co_return router_.eth_version;
}

Task<api_common::Service::NodeInfos> DirectService::node_infos() {
    co_return api_common::Service::NodeInfos{router_.node_info_provider()};
}

static Task<api_common::Service::PeerKeys> do_send_message_call(
    const ServiceRouter& router,
    common::Message message,
    api_common::PeerFilter peer_filter) {
    auto executor = co_await this_coro::executor;
    SendMessageCall call{std::move(message), std::move(peer_filter), executor};
    co_await router.send_message_channel.send(call);
    co_return (co_await call.result());
}

Task<api_common::Service::PeerKeys> DirectService::send_message_by_id(common::Message message, common::EccPublicKey public_key) {
    co_return (co_await do_send_message_call(router_, std::move(message), api_common::PeerFilter::with_peer_public_key(std::move(public_key))));
}

Task<api_common::Service::PeerKeys> DirectService::send_message_to_random_peers(common::Message message, size_t max_peers) {
    co_return (co_await do_send_message_call(router_, std::move(message), api_common::PeerFilter::with_max_peers(max_peers)));
}

Task<api_common::Service::PeerKeys> DirectService::send_message_to_all(common::Message message) {
    co_return (co_await do_send_message_call(router_, std::move(message), api::api_common::PeerFilter{}));
}

Task<api_common::Service::PeerKeys> DirectService::send_message_by_min_block(common::Message message, size_t max_peers) {
    co_return (co_await do_send_message_call(router_, std::move(message), api_common::PeerFilter::with_max_peers(max_peers)));
}

Task<void> DirectService::peer_min_block(common::EccPublicKey /*public_key*/) {
    // TODO: implement
    co_return;
}

Task<void> DirectService::messages(
    api_common::MessageIdSet message_id_filter,
    std::function<Task<void>(api_common::MessageFromPeer)> consumer) {
    auto executor = co_await this_coro::executor;
    MessagesCall call{std::move(message_id_filter), executor};

    auto unsubscribe_signal = call.unsubscribe_signal();
    auto _ = gsl::finally([=]() { unsubscribe_signal->notify(); });

    co_await router_.message_calls_channel.send(call);
    auto channel = co_await call.result();

    // loop until a cancelled exception
    while (true) {
        auto message = co_await channel->receive();
        co_await consumer(std::move(message));
    }
}

Task<api_common::PeerInfos> DirectService::peers() {
    auto executor = co_await this_coro::executor;
    auto call = std::make_shared<concurrency::AwaitablePromise<api_common::PeerInfos>>(executor);
    auto call_future = call->get_future();
    co_await router_.peers_calls_channel.send(call);
    co_return (co_await call_future.get_async());
}

Task<size_t> DirectService::peer_count() {
    auto executor = co_await this_coro::executor;
    auto call = std::make_shared<concurrency::AwaitablePromise<size_t>>(executor);
    auto call_future = call->get_future();
    co_await router_.peer_count_calls_channel.send(call);
    co_return (co_await call_future.get_async());
}

Task<std::optional<api_common::PeerInfo>> DirectService::peer_by_id(common::EccPublicKey public_key) {
    auto executor = co_await this_coro::executor;
    PeerCall call{std::move(public_key), executor};
    auto call_future = call.result_promise->get_future();
    co_await router_.peer_calls_channel.send(call);
    co_return (co_await call_future.get_async());
}

Task<void> DirectService::penalize_peer(common::EccPublicKey public_key) {
    co_await router_.peer_penalize_calls_channel.send({std::move(public_key)});
}

Task<void> DirectService::peer_events(
    std::function<Task<void>(api_common::PeerEvent)> consumer) {
    auto executor = co_await this_coro::executor;
    PeerEventsCall call{executor};
    auto call_future = call.result_promise->get_future();

    auto unsubscribe_signal = call.unsubscribe_signal;
    auto _ = gsl::finally([=]() { unsubscribe_signal->notify(); });

    co_await router_.peer_events_calls_channel.send(call);
    auto channel = co_await call_future.get_async();

    // loop until a cancelled exception
    while (true) {
        auto event = co_await channel->receive();
        co_await consumer(std::move(event));
    }
}

}  // namespace silkworm::sentry::api::router
