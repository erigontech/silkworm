// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <list>
#include <memory>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/infra/concurrency/event_notifier.hpp>
#include <silkworm/infra/concurrency/task_group.hpp>
#include <silkworm/sentry/api/common/message_from_peer.hpp>
#include <silkworm/sentry/api/common/message_id_set.hpp>
#include <silkworm/sentry/api/router/messages_call.hpp>

#include "peer_manager.hpp"
#include "peer_manager_observer.hpp"

namespace silkworm::sentry {

class MessageReceiver : public PeerManagerObserver {
  public:
    MessageReceiver(const boost::asio::any_io_executor& executor, size_t max_peers)
        : message_calls_channel_(executor),
          strand_(boost::asio::make_strand(executor)),
          peer_tasks_(strand_, max_peers),
          unsubscription_tasks_(strand_, 1000) {}

    ~MessageReceiver() override = default;

    concurrency::Channel<api::router::MessagesCall>& message_calls_channel() {
        return message_calls_channel_;
    }

    static Task<void> run(std::shared_ptr<MessageReceiver> self, PeerManager& peer_manager);

  private:
    Task<void> handle_calls();
    Task<void> unsubscribe_on_signal(std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal);
    Task<void> receive_messages(std::shared_ptr<rlpx::Peer> peer);

    // PeerManagerObserver
    void on_peer_added(std::shared_ptr<rlpx::Peer> peer) override;
    void on_peer_removed(std::shared_ptr<rlpx::Peer> peer) override;
    void on_peer_connect_error(const EnodeUrl& peer_url) override;
    Task<void> on_peer_added_in_strand(std::shared_ptr<rlpx::Peer> peer);

    concurrency::Channel<api::router::MessagesCall> message_calls_channel_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;
    concurrency::TaskGroup peer_tasks_;
    concurrency::TaskGroup unsubscription_tasks_;

    struct Subscription {
        std::shared_ptr<concurrency::Channel<api::MessageFromPeer>> messages_channel;
        api::MessageIdSet message_id_filter;
        std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal;
    };

    std::list<Subscription> subscriptions_;
};

}  // namespace silkworm::sentry
