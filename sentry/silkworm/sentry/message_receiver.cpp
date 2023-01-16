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

#include <memory>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

namespace silkworm::sentry {

using namespace boost::asio;

awaitable<void> MessageReceiver::start(std::shared_ptr<MessageReceiver> self, PeerManager& peer_manager) {
    peer_manager.add_observer(std::weak_ptr(self));

    co_await co_spawn(self->strand_, self->handle_calls(), use_awaitable);
}

awaitable<void> MessageReceiver::handle_calls() {
    auto executor = co_await this_coro::executor;

    while (true) {
        auto call = co_await message_calls_channel_.receive();

        auto messages_channel = std::make_shared<common::Channel<rpc::common::MessagesCall::MessageFromPeer>>(executor);

        subscriptions_.push_back({
            messages_channel,
            call.message_id_filter(),
            call.unsubscribe_signal_channel(),
        });

        co_spawn(executor, unsubscribe_on_signal(call.unsubscribe_signal_channel()), detached);

        co_await call.set_result(messages_channel);
    }
}

awaitable<void> MessageReceiver::unsubscribe_on_signal(std::shared_ptr<common::Channel<std::monostate>> unsubscribe_signal_channel) {
    try {
        co_await unsubscribe_signal_channel->receive();
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == experimental::error::channel_closed) {
            subscriptions_.remove_if([=](const Subscription& subscription) {
                return subscription.unsubscribe_signal_channel == unsubscribe_signal_channel;
            });
            co_return;
        }
        throw;
    }
}

awaitable<void> MessageReceiver::receive_messages(std::shared_ptr<rlpx::Peer> peer) {
    while (true) {
        auto message = co_await peer->receive_message();

        rpc::common::MessagesCall::MessageFromPeer message_from_peer{
            std::move(message),
            {peer->peer_public_key()},
        };

        for (auto& subscription : subscriptions_) {
            if (subscription.message_id_filter.empty() || subscription.message_id_filter.contains(message_from_peer.message.id)) {
                co_await subscription.messages_channel->send(message_from_peer);
            }
        }
    }
}

// PeerManagerObserver
void MessageReceiver::on_peer_added(std::shared_ptr<rlpx::Peer> peer) {
    co_spawn(strand_, on_peer_added_in_strand(std::move(peer)), detached);
}

// PeerManagerObserver
void MessageReceiver::on_peer_removed(std::shared_ptr<rlpx::Peer> /*peer*/) {
}

awaitable<void> MessageReceiver::on_peer_added_in_strand(std::shared_ptr<rlpx::Peer> peer) {
    co_await receive_messages(peer);
}

}  // namespace silkworm::sentry
