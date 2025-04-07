// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "peer_manager_api.hpp"

#include <optional>
#include <string>
#include <vector>

#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/infra/concurrency/spawn.hpp>
#include <silkworm/sentry/rlpx/common/disconnect_reason.hpp>

namespace silkworm::sentry {

using namespace boost::asio;

Task<void> PeerManagerApi::run(std::shared_ptr<PeerManagerApi> self) {
    using namespace concurrency::awaitable_wait_for_all;

    self->peer_manager_.add_observer(std::weak_ptr(self));

    auto run =
        self->handle_peer_count_calls() &&
        self->handle_peers_calls() &&
        self->handle_peer_calls() &&
        self->handle_peer_penalize_calls() &&
        self->handle_peer_events_calls() &&
        self->events_unsubscription_tasks_.wait() &&
        self->forward_peer_events();
    co_await concurrency::spawn_task(self->strand_, std::move(run));
}

Task<void> PeerManagerApi::handle_peer_count_calls() {
    // loop until receive() throws a cancelled exception
    while (true) {
        auto call = co_await peer_count_calls_channel_.receive();
        size_t count = co_await peer_manager_.count_peers();
        call->set_value(count);
    }
}

static std::optional<api::PeerInfo> make_peer_info(rlpx::Peer& peer) {
    auto url_opt = peer.url();
    if (!url_opt) return std::nullopt;
    auto peer_public_key_opt = peer.peer_public_key();
    if (!peer_public_key_opt) return std::nullopt;
    auto hello_message_opt = peer.hello_message();
    if (!hello_message_opt) return std::nullopt;
    auto& hello_message = hello_message_opt.value();

    std::vector<std::string> capabilities;
    for (auto& capability : hello_message.capabilities()) {
        capabilities.push_back(capability.to_string());
    }

    return api::PeerInfo{
        url_opt.value(),
        peer.local_endpoint(),
        peer.remote_endpoint(),
        peer.is_inbound(),
        peer.is_static(),
        std::string{hello_message.client_id()},
        std::move(capabilities),
    };
}

Task<void> PeerManagerApi::handle_peers_calls() {
    // loop until receive() throws a cancelled exception
    while (true) {
        auto call = co_await peers_calls_channel_.receive();

        api::PeerInfos peers;
        co_await peer_manager_.enumerate_peers([&peers](const std::shared_ptr<rlpx::Peer>& peer) {
            auto info_opt = make_peer_info(*peer);
            if (info_opt) {
                peers.push_back(info_opt.value());
            }
        });

        call->set_value(peers);
    }
}

Task<void> PeerManagerApi::handle_peer_calls() {
    // loop until receive() throws a cancelled exception
    while (true) {
        auto call = co_await peer_calls_channel_.receive();
        auto peer_public_key_opt = call.peer_public_key;

        std::optional<api::PeerInfo> info_opt;
        co_await peer_manager_.enumerate_peers([&info_opt, &peer_public_key_opt](const std::shared_ptr<rlpx::Peer>& peer) {
            auto key_opt = peer->peer_public_key();
            if (key_opt && peer_public_key_opt && (key_opt.value() == peer_public_key_opt.value())) {
                info_opt = make_peer_info(*peer);
            }
        });

        call.result_promise->set_value(info_opt);
    }
}

Task<void> PeerManagerApi::handle_peer_penalize_calls() {
    // loop until receive() throws a cancelled exception
    while (true) {
        auto peer_public_key_opt = co_await peer_penalize_calls_channel_.receive();

        co_await peer_manager_.enumerate_peers([&peer_public_key_opt](const std::shared_ptr<rlpx::Peer>& peer) {
            auto key_opt = peer->peer_public_key();
            if (key_opt && peer_public_key_opt && (key_opt.value() == peer_public_key_opt.value())) {
                peer->disconnect(rlpx::DisconnectReason::kDisconnectRequested);
            }
        });
    }
}

Task<void> PeerManagerApi::handle_peer_events_calls() {
    auto executor = co_await this_coro::executor;

    // loop until receive() throws a cancelled exception
    while (true) {
        auto call = co_await peer_events_calls_channel_.receive();

        SILK_TRACE_M("sentry") << "PeerManagerApi::handle_peer_events_calls adding subscription";

        auto events_channel = std::make_shared<concurrency::Channel<api::PeerEvent>>(executor);

        events_subscriptions_.push_back({
            events_channel,
            call.unsubscribe_signal,
        });

        events_unsubscription_tasks_.spawn(executor, unsubscribe_peer_events_on_signal(call.unsubscribe_signal));

        call.result_promise->set_value(events_channel);
    }
}

Task<void> PeerManagerApi::unsubscribe_peer_events_on_signal(std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal) {
    try {
        co_await unsubscribe_signal->wait();
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled) {
            SILK_TRACE_M("sentry") << "PeerManagerApi::unsubscribe_events_on_signal cancelled";
            co_return;
        }
        SILK_ERROR_M("sentry") << "PeerManagerApi::unsubscribe_events_on_signal system_error: " << ex.what();
        throw;
    } catch (const std::exception& ex) {
        SILK_ERROR_M("sentry") << "PeerManagerApi::unsubscribe_events_on_signal exception: " << ex.what();
        throw;
    }

    auto subscription = std::find_if(events_subscriptions_.begin(), events_subscriptions_.end(), [=](const Subscription& s) {
        return s.unsubscribe_signal == unsubscribe_signal;
    });
    if (subscription != events_subscriptions_.end()) {
        subscription->events_channel->close();
        events_subscriptions_.erase(subscription);
    }
}

Task<void> PeerManagerApi::forward_peer_events() {
    // loop until receive() throws a cancelled exception
    while (true) {
        auto event = co_await peer_events_channel_.receive();

        SILK_TRACE_M("sentry") << "PeerManagerApi::forward_peer_events forwarding an event to subscribers";

        for (auto& subscription : events_subscriptions_) {
            try {
                co_await subscription.events_channel->send(event);
            } catch (const boost::system::system_error& ex) {
                if (ex.code() == experimental::error::channel_closed) {
                    continue;
                }
                throw;
            }
        }
    }
}

// PeerManagerObserver
void PeerManagerApi::on_peer_added(std::shared_ptr<rlpx::Peer> peer) {
    api::PeerEvent event{
        peer->peer_public_key(),
        api::PeerEventId::kAdded,
    };
    bool ok = peer_events_channel_.try_send(std::move(event));
    if (!ok) {
        SILK_WARN_M("sentry") << "PeerManagerApi::on_peer_added too many unprocessed events, ignoring an event";
    }
}

// PeerManagerObserver
void PeerManagerApi::on_peer_removed(std::shared_ptr<rlpx::Peer> peer) {
    api::PeerEvent event{
        peer->peer_public_key(),
        api::PeerEventId::kRemoved,
    };
    bool ok = peer_events_channel_.try_send(std::move(event));
    if (!ok) {
        SILK_WARN_M("sentry") << "PeerManagerApi::on_peer_removed too many unprocessed events, ignoring an event";
    }
}

// PeerManagerObserver
void PeerManagerApi::on_peer_connect_error(const EnodeUrl& /*peer_url*/) {
}

}  // namespace silkworm::sentry
