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

#pragma once

#include <list>
#include <memory>
#include <variant>

#include <silkworm/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>

#include <silkworm/sentry/common/channel.hpp>
#include <silkworm/sentry/rpc/common/messages_call.hpp>

#include "peer_manager.hpp"

namespace silkworm::sentry {

class MessageReceiver : public PeerManagerObserver {
  public:
    explicit MessageReceiver(boost::asio::io_context& io_context)
        : message_calls_channel_(io_context),
          strand_(boost::asio::make_strand(io_context)) {}

    ~MessageReceiver() override = default;

    common::Channel<rpc::common::MessagesCall>& message_calls_channel() {
        return message_calls_channel_;
    }

    static boost::asio::awaitable<void> start(std::shared_ptr<MessageReceiver> self, PeerManager& peer_manager);

  private:
    boost::asio::awaitable<void> handle_calls();
    boost::asio::awaitable<void> unsubscribe_on_signal(std::shared_ptr<common::Channel<std::monostate>> unsubscribe_signal_channel);
    boost::asio::awaitable<void> receive_messages(std::shared_ptr<rlpx::Peer> peer);

    // PeerManagerObserver
    void on_peer_added(std::shared_ptr<rlpx::Peer> peer) override;
    void on_peer_removed(std::shared_ptr<rlpx::Peer> peer) override;
    boost::asio::awaitable<void> on_peer_added_in_strand(std::shared_ptr<rlpx::Peer> peer);

    common::Channel<rpc::common::MessagesCall> message_calls_channel_;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;

    struct Subscription {
        std::shared_ptr<common::Channel<rpc::common::MessagesCall::MessageFromPeer>> messages_channel;
        rpc::common::MessagesCall::MessageIdSet message_id_filter;
        std::shared_ptr<common::Channel<std::monostate>> unsubscribe_signal_channel;
    };

    std::list<Subscription> subscriptions_;
};

}  // namespace silkworm::sentry
