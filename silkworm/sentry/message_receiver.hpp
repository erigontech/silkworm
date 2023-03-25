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

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>

#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/infra/concurrency/event_notifier.hpp>
#include <silkworm/sentry/api/api_common/message_from_peer.hpp>
#include <silkworm/sentry/api/api_common/message_id_set.hpp>
#include <silkworm/sentry/api/router/messages_call.hpp>
#include <silkworm/sentry/common/task_group.hpp>

#include "peer_manager.hpp"

namespace silkworm::sentry {

class MessageReceiver : public PeerManagerObserver {
  public:
    MessageReceiver(boost::asio::io_context& io_context, size_t max_peers)
        : message_calls_channel_(io_context),
          strand_(boost::asio::make_strand(io_context)),
          peer_tasks_(strand_, max_peers),
          unsubscription_tasks_(strand_, 1000) {}

    ~MessageReceiver() override = default;

    concurrency::Channel<api::router::MessagesCall>& message_calls_channel() {
        return message_calls_channel_;
    }

    static boost::asio::awaitable<void> start(std::shared_ptr<MessageReceiver> self, PeerManager& peer_manager);

  private:
    boost::asio::awaitable<void> handle_calls();
    boost::asio::awaitable<void> unsubscribe_on_signal(std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal);
    boost::asio::awaitable<void> receive_messages(std::shared_ptr<rlpx::Peer> peer);

    // PeerManagerObserver
    void on_peer_added(std::shared_ptr<rlpx::Peer> peer) override;
    void on_peer_removed(std::shared_ptr<rlpx::Peer> peer) override;
    boost::asio::awaitable<void> on_peer_added_in_strand(std::shared_ptr<rlpx::Peer> peer);

    concurrency::Channel<api::router::MessagesCall> message_calls_channel_;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;
    common::TaskGroup peer_tasks_;
    common::TaskGroup unsubscription_tasks_;

    struct Subscription {
        std::shared_ptr<concurrency::Channel<api::api_common::MessageFromPeer>> messages_channel;
        api::api_common::MessageIdSet message_id_filter;
        std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal;
    };

    std::list<Subscription> subscriptions_;
};

}  // namespace silkworm::sentry
