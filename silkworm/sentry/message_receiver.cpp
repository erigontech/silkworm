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

#include "message_receiver.hpp"

#include <algorithm>
#include <memory>

#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/infra/concurrency/co_spawn_sw.hpp>

namespace silkworm::sentry {

using namespace boost::asio;

Task<void> MessageReceiver::start(std::shared_ptr<MessageReceiver> self, PeerManager& peer_manager) {
    using namespace concurrency::awaitable_wait_for_all;

    peer_manager.add_observer(std::weak_ptr(self));

    auto start =
        self->peer_tasks_.wait() &&
        self->unsubscription_tasks_.wait() &&
        self->handle_calls();
    co_await concurrency::co_spawn_sw(self->strand_, std::move(start), use_awaitable);
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
            log::Trace("sentry") << "MessageReceiver::unsubscribe_on_signal cancelled";
            co_return;
        }
        log::Error("sentry") << "MessageReceiver::unsubscribe_on_signal system_error: " << ex.what();
        throw;
    } catch (const std::exception& ex) {
        log::Error("sentry") << "MessageReceiver::unsubscribe_on_signal exception: " << ex.what();
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
        } catch (const rlpx::Peer::DisconnectedError& ex) {
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
            log::Debug("sentry") << "MessageReceiver::on_peer_added_in_strand cancelled";
            co_return;
        }
        log::Error("sentry") << "MessageReceiver::on_peer_added_in_strand system_error: " << ex.what();
        throw;
    } catch (const std::exception& ex) {
        log::Error("sentry") << "MessageReceiver::on_peer_added_in_strand exception: " << ex.what();
        throw;
    }
}

}  // namespace silkworm::sentry
