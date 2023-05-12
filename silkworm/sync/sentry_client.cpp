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

#include <future>
#include <optional>

#include <boost/asio/co_spawn.hpp>

#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/sentry/eth/message_id.hpp>

#include "messages/inbound_block_bodies.hpp"
#include "messages/inbound_block_headers.hpp"
#include "messages/inbound_get_block_bodies.hpp"
#include "messages/inbound_get_block_headers.hpp"
#include "messages/inbound_new_block.hpp"
#include "messages/inbound_new_block_hashes.hpp"

namespace silkworm {

using namespace boost::asio;

SentryClient::SentryClient(
    boost::asio::io_context& io_context,
    std::shared_ptr<silkworm::sentry::api::api_common::SentryClient> sentry_client)
    : io_context_{io_context},
      sentry_client_{std::move(sentry_client)},
      tasks_{io_context, 1000} {
}

static std::unique_ptr<InboundMessage> decode_inbound_message(const silkworm::sentry::api::api_common::MessageFromPeer& message_from_peer) {
    using sentry::eth::MessageId;
    auto eth_message_id = sentry::eth::eth_message_id_from_common_id(message_from_peer.message.id);
    PeerId peer_id = message_from_peer.peer_public_key->serialized();
    ByteView raw_message{message_from_peer.message.data};
    switch (eth_message_id) {
        case MessageId::kGetBlockHeaders:
            return std::make_unique<InboundGetBlockHeaders>(raw_message, peer_id);
        case MessageId::kGetBlockBodies:
            return std::make_unique<InboundGetBlockBodies>(raw_message, peer_id);
        case MessageId::kNewBlockHashes:
            return std::make_unique<InboundNewBlockHashes>(raw_message, peer_id);
        case MessageId::kNewBlock:
            return std::make_unique<InboundNewBlock>(raw_message, peer_id);
        case MessageId::kBlockHeaders:
            return std::make_unique<InboundBlockHeaders>(raw_message, peer_id);
        case MessageId::kBlockBodies:
            return std::make_unique<InboundBlockBodies>(raw_message, peer_id);
        default:
            return {};
    }
}

static constexpr std::string_view kLogTitle{"sync::SentryClient"};

boost::asio::awaitable<void> SentryClient::publish(const silkworm::sentry::api::api_common::MessageFromPeer& message_from_peer) {
    using sentry::eth::MessageId;
    auto eth_message_id = sentry::eth::eth_message_id_from_common_id(message_from_peer.message.id);

    std::shared_ptr<InboundMessage> message;
    std::optional<PeerId> penalize_peer_id;
    try {
        message = std::shared_ptr(decode_inbound_message(message_from_peer));
    } catch (DecodingException& error) {
        PeerId peer_id = message_from_peer.peer_public_key->serialized();
        log::Warning(kLogTitle) << "received and ignored a malformed message, peer= " << human_readable_id(peer_id)
                                << ", msg-id= " << static_cast<int>(message_from_peer.message.id)
                                << " - " << error.what();
        penalize_peer_id = std::move(peer_id);
    }

    received_message_size_subscription(message_from_peer.message.data.size());

    if (penalize_peer_id) {
        malformed_message_subscription();
        co_await penalize_peer_async(penalize_peer_id.value(), BadBlockPenalty);
        co_return;
    }

    if (!message) {
        log::Warning(kLogTitle) << "InboundMessage " << static_cast<int>(eth_message_id) << " received but ignored";
        co_return;
    }

    switch (eth_message_id) {
        case MessageId::kGetBlockHeaders:
        case MessageId::kGetBlockBodies:
            requests_subscription(message);
            break;
        case MessageId::kBlockHeaders:
        case MessageId::kBlockBodies:
        case MessageId::kNewBlockHashes:
        case MessageId::kNewBlock:
            announcements_subscription(message);
            break;
        default:
            rest_subscription(message);
            break;
    }
}

static silkworm::sentry::api::api_common::MessageIdSet make_message_id_filter() {
    using namespace sentry::eth;
    silkworm::sentry::api::api_common::MessageIdSet ids = {
        common_message_id_from_eth_id(MessageId::kGetBlockHeaders),
        common_message_id_from_eth_id(MessageId::kGetBlockBodies),

        common_message_id_from_eth_id(MessageId::kBlockHeaders),
        common_message_id_from_eth_id(MessageId::kBlockBodies),
        common_message_id_from_eth_id(MessageId::kNewBlockHashes),
        common_message_id_from_eth_id(MessageId::kNewBlock),
    };
    return ids;
}

template <typename T>
static awaitable<void> resolve_promise_with_awaitable_result(std::promise<T>& promise, awaitable<T> task) {
    try {
        promise.set_value(co_await std::move(task));
    } catch (...) {
        promise.set_exception(std::current_exception());
    }
}

template <>
awaitable<void> resolve_promise_with_awaitable_result(std::promise<void>& promise, awaitable<void> task) {
    try {
        co_await std::move(task);
        promise.set_value();
    } catch (...) {
        promise.set_exception(std::current_exception());
    }
}

template <typename T>
static T sync_spawn(concurrency::TaskGroup& tasks, io_context& io_context, awaitable<T> task) {
    std::promise<T> promise;
    tasks.spawn(io_context, resolve_promise_with_awaitable_result(promise, std::move(task)));
    return promise.get_future().get();
}

static sentry::common::Message sentry_message_from_outbound_message(const OutboundMessage& outbound_message) {
    return sentry::common::Message{
        sentry::eth::common_message_id_from_eth_id(outbound_message.eth_message_id()),
        outbound_message.message_data(),
    };
}

static SentryClient::PeerIds peer_ids_from_peer_keys(const silkworm::sentry::api::api_common::Service::PeerKeys& peer_keys) {
    SentryClient::PeerIds peer_ids;
    for (auto& peer_key : peer_keys) {
        peer_ids.push_back(peer_key.serialized());
    }
    return peer_ids;
}

awaitable<SentryClient::PeerIds> SentryClient::send_message_by_id_async(const OutboundMessage& outbound_message, const PeerId& peer_id) {
    auto message = sentry_message_from_outbound_message(outbound_message);
    auto peer_public_key = sentry::common::EccPublicKey::deserialize(peer_id);
    auto service = co_await sentry_client_->service();
    auto peer_keys = co_await service->send_message_by_id(std::move(message), std::move(peer_public_key));
    co_return peer_ids_from_peer_keys(peer_keys);
}

SentryClient::PeerIds SentryClient::send_message_by_id(const OutboundMessage& outbound_message, const PeerId& peer_id) {
    return sync_spawn(tasks_, io_context_, send_message_by_id_async(outbound_message, peer_id));
}

awaitable<SentryClient::PeerIds> SentryClient::send_message_to_random_peers_async(const OutboundMessage& outbound_message, size_t max_peers) {
    auto message = sentry_message_from_outbound_message(outbound_message);
    auto service = co_await sentry_client_->service();
    auto peer_keys = co_await service->send_message_to_random_peers(std::move(message), max_peers);
    co_return peer_ids_from_peer_keys(peer_keys);
}

SentryClient::PeerIds SentryClient::send_message_to_random_peers(const OutboundMessage& outbound_message, size_t max_peers) {
    return sync_spawn(tasks_, io_context_, send_message_to_random_peers_async(outbound_message, max_peers));
}

awaitable<SentryClient::PeerIds> SentryClient::send_message_to_all_async(const OutboundMessage& outbound_message) {
    auto message = sentry_message_from_outbound_message(outbound_message);
    auto service = co_await sentry_client_->service();
    auto peer_keys = co_await service->send_message_to_all(std::move(message));
    co_return peer_ids_from_peer_keys(peer_keys);
}

SentryClient::PeerIds SentryClient::send_message_to_all(const OutboundMessage& outbound_message) {
    return sync_spawn(tasks_, io_context_, send_message_to_all_async(outbound_message));
}

awaitable<SentryClient::PeerIds> SentryClient::send_message_by_min_block_async(const OutboundMessage& outbound_message, BlockNum /*min_block*/, size_t max_peers) {
    auto message = sentry_message_from_outbound_message(outbound_message);
    auto service = co_await sentry_client_->service();
    auto peer_keys = co_await service->send_message_by_min_block(std::move(message), max_peers);
    co_return peer_ids_from_peer_keys(peer_keys);
}

SentryClient::PeerIds SentryClient::send_message_by_min_block(const OutboundMessage& outbound_message, BlockNum min_block, size_t max_peers) {
    return sync_spawn(tasks_, io_context_, send_message_by_min_block_async(outbound_message, min_block, max_peers));
}

awaitable<void> SentryClient::peer_min_block_async(const PeerId& peer_id, BlockNum /*min_block*/) {
    auto peer_public_key = sentry::common::EccPublicKey::deserialize(peer_id);
    auto service = co_await sentry_client_->service();
    co_await service->peer_min_block(std::move(peer_public_key));
}

void SentryClient::peer_min_block(const PeerId& peer_id, BlockNum min_block) {
    sync_spawn(tasks_, io_context_, peer_min_block_async(peer_id, min_block));
}

boost::asio::awaitable<void> SentryClient::async_run() {
    using namespace concurrency::awaitable_wait_for_all;

    co_await (receive_messages() && receive_peer_events() && tasks_.wait());
}

boost::asio::awaitable<void> SentryClient::receive_messages() {
    std::function<awaitable<void>(silkworm::sentry::api::api_common::MessageFromPeer)> consumer = [this](auto message_from_peer) -> awaitable<void> {
        co_await this->publish(message_from_peer);
    };

    auto service = co_await sentry_client_->service();
    co_await service->messages(make_message_id_filter(), std::move(consumer));
}

boost::asio::awaitable<void> SentryClient::on_peer_event(silkworm::sentry::api::api_common::PeerEvent event) {
    auto peer_id = event.peer_public_key->serialized();
    std::string event_desc;
    std::string info;

    if (event.event_id == silkworm::sentry::api::api_common::PeerEventId::kAdded) {
        event_desc = "connected";
        active_peers_++;

        try {
            info = co_await request_peer_info_async(peer_id);
        } catch (std::exception) {
            info = "unknown";  // workaround for EnodeUrl fragility
        }

        peer_infos_[peer_id] = info;
    } else {
        event_desc = "disconnected";
        if (active_peers_ > 0) active_peers_--;

        info = peer_infos_[peer_id];
        peer_infos_.erase(peer_id);
    }

    log::Info(kLogTitle) << "Peer " << human_readable_id(peer_id)
                         << " " << event_desc
                         << ", active " << active_peers()
                         << ", info: " << info;
}

boost::asio::awaitable<void> SentryClient::receive_peer_events() {
    // Get the current active peers count.
    // This initial value is later updated by on_peer_event.
    log::Info(kLogTitle) << (co_await count_active_peers_async()) << " active peers";

    std::function<awaitable<void>(silkworm::sentry::api::api_common::PeerEvent)> consumer = [this](auto event) -> awaitable<void> {
        co_await this->on_peer_event(event);
    };

    auto service = co_await sentry_client_->service();
    co_await service->peer_events(std::move(consumer));
}

awaitable<uint64_t> SentryClient::count_active_peers_async() {
    auto service = co_await sentry_client_->service();
    size_t peer_count = co_await service->peer_count();
    active_peers_.store(peer_count);
    co_return peer_count;
}

uint64_t SentryClient::count_active_peers() {
    return sync_spawn(tasks_, io_context_, count_active_peers_async());
}

boost::asio::awaitable<std::string> SentryClient::request_peer_info_async(PeerId peer_id) {
    auto peer_public_key = sentry::common::EccPublicKey::deserialize(peer_id);
    auto service = co_await sentry_client_->service();
    auto peer_info_opt = co_await service->peer_by_id(std::move(peer_public_key));

    if (!peer_info_opt) {
        co_return "-info-not-found-";
    } else {
        auto peer_info = peer_info_opt.value();
        std::string info = "client_id=" + peer_info.client_id + " / enode_url=" + peer_info.url.to_string();
        co_return info;
    }
}

std::string SentryClient::request_peer_info(PeerId peer_id) {
    return sync_spawn(tasks_, io_context_, this->request_peer_info_async(std::move(peer_id)));
}

boost::asio::awaitable<void> SentryClient::penalize_peer_async(PeerId peer_id, Penalty penalty) {
    if (penalty == Penalty::NoPenalty) {
        co_return;
    }
    auto peer_public_key = sentry::common::EccPublicKey::deserialize(peer_id);
    auto service = co_await sentry_client_->service();
    co_await service->penalize_peer(std::move(peer_public_key));
}

void SentryClient::penalize_peer(PeerId peer_id, Penalty penalty) {
    sync_spawn(tasks_, io_context_, this->penalize_peer_async(std::move(peer_id), penalty));
}

uint64_t SentryClient::active_peers() {
    return active_peers_.load();
}

}  // namespace silkworm
