// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "message_receiver.hpp"

#include <algorithm>
#include <memory>

#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/infra/concurrency/spawn.hpp>

namespace silkworm::sentry {

using namespace boost::asio;

Task<void> MessageReceiver::run(std::shared_ptr<MessageReceiver> self, PeerManager& peer_manager) {
    using namespace concurrency::awaitable_wait_for_all;

    peer_manager.add_observer(std::weak_ptr(self));

    try {
        auto run =
            self->peer_tasks_.wait() &&
            self->unsubscription_tasks_.wait() &&
            self->handle_calls();
        co_await concurrency::spawn_task(self->strand_, std::move(run));
    } catch (const boost::system::system_error& ex) {
        SILK_ERROR_M("sentry") << "MessageReceiver::run ex=" << ex.what();
        if (ex.code() == boost::system::errc::operation_canceled) {
            // TODO(canepat) demote to debug after https://github.com/erigontech/silkworm/issues/2333 is solved
            SILK_WARN_M("sentry") << "MessageReceiver::run operation_canceled";
        }
        throw;
    }
}

Task<void> MessageReceiver::handle_calls() {
    auto executor = co_await this_coro::executor;

    // loop until receive() throws a cancelled exception
    while (true) {
        auto call = co_await message_calls_channel_.receive();

        auto messages_channel = std::make_shared<concurrency::Channel<api::MessageFromPeer>>(executor);

        subscriptions_.push_back({
            messages_channel,
            call.message_id_filter(),
            call.unsubscribe_signal(),
        });

        unsubscription_tasks_.spawn(executor, unsubscribe_on_signal(call.unsubscribe_signal()));

        call.set_result(messages_channel);
    }
}

Task<void> MessageReceiver::unsubscribe_on_signal(std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal) {
    try {
        co_await unsubscribe_signal->wait();
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled) {
            SILK_TRACE_M("sentry") << "MessageReceiver::unsubscribe_on_signal cancelled";
            co_return;
        }
        SILK_ERROR_M("sentry") << "MessageReceiver::unsubscribe_on_signal system_error: " << ex.what();
        throw;
    } catch (const std::exception& ex) {
        SILK_ERROR_M("sentry") << "MessageReceiver::unsubscribe_on_signal exception: " << ex.what();
        throw;
    }

    auto subscription = std::find_if(subscriptions_.begin(), subscriptions_.end(), [=](const Subscription& s) {
        return s.unsubscribe_signal == unsubscribe_signal;
    });
    if (subscription != subscriptions_.end()) {
        subscription->messages_channel->close();
        subscriptions_.erase(subscription);
    }
}

Task<void> MessageReceiver::receive_messages(std::shared_ptr<rlpx::Peer> peer) {
    // loop until DisconnectedError
    while (true) {
        Message message;
        try {
            message = co_await peer->receive_message();
        } catch (const rlpx::Peer::DisconnectedError&) {
            break;
        }

        api::MessageFromPeer message_from_peer{
            std::move(message),
            {peer->peer_public_key()},
        };

        std::list<std::shared_ptr<concurrency::Channel<api::MessageFromPeer>>> messages_channels;
        for (auto& subscription : subscriptions_) {
            if (subscription.message_id_filter.empty() || subscription.message_id_filter.contains(message_from_peer.message.id)) {
                messages_channels.push_back(subscription.messages_channel);
            }
        }

        for (auto& messages_channel : messages_channels) {
            try {
                co_await messages_channel->send(message_from_peer);
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
void MessageReceiver::on_peer_added(std::shared_ptr<rlpx::Peer> peer) {
    peer_tasks_.spawn(strand_, on_peer_added_in_strand(std::move(peer)));
}

// PeerManagerObserver
void MessageReceiver::on_peer_removed(std::shared_ptr<rlpx::Peer> /*peer*/) {
}

// PeerManagerObserver
void MessageReceiver::on_peer_connect_error(const EnodeUrl& /*peer_url*/) {
}

Task<void> MessageReceiver::on_peer_added_in_strand(std::shared_ptr<rlpx::Peer> peer) {
    try {
        co_await receive_messages(peer);
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled) {
            SILK_DEBUG_M("sentry") << "MessageReceiver::on_peer_added_in_strand cancelled";
            co_return;
        }
        SILK_ERROR_M("sentry") << "MessageReceiver::on_peer_added_in_strand system_error: " << ex.what();
        throw;
    } catch (const std::exception& ex) {
        SILK_ERROR_M("sentry") << "MessageReceiver::on_peer_added_in_strand exception: " << ex.what();
        throw;
    }
}

}  // namespace silkworm::sentry
