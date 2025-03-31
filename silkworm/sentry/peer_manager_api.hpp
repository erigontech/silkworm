// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <list>
#include <memory>
#include <optional>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <silkworm/infra/concurrency/awaitable_future.hpp>
#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/infra/concurrency/event_notifier.hpp>
#include <silkworm/infra/concurrency/task_group.hpp>
#include <silkworm/sentry/api/common/peer_event.hpp>
#include <silkworm/sentry/api/common/peer_info.hpp>
#include <silkworm/sentry/api/router/peer_call.hpp>
#include <silkworm/sentry/api/router/peer_events_call.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>

#include "peer_manager.hpp"
#include "peer_manager_observer.hpp"
#include "rlpx/peer.hpp"

namespace silkworm::sentry {

class PeerManagerApi : public PeerManagerObserver {
  public:
    explicit PeerManagerApi(
        const boost::asio::any_io_executor& executor,
        PeerManager& peer_manager)
        : peer_manager_(peer_manager),
          peer_count_calls_channel_(executor),
          peers_calls_channel_(executor),
          peer_calls_channel_(executor),
          peer_penalize_calls_channel_(executor),
          peer_events_calls_channel_(executor),
          strand_(boost::asio::make_strand(executor)),
          events_unsubscription_tasks_(strand_, 1000),
          peer_events_channel_(executor, 1000) {}

    static Task<void> run(std::shared_ptr<PeerManagerApi> self);

    template <typename T>
    using Channel = concurrency::Channel<T>;

    Channel<std::shared_ptr<concurrency::AwaitablePromise<size_t>>>& peer_count_calls_channel() {
        return peer_count_calls_channel_;
    }

    Channel<std::shared_ptr<concurrency::AwaitablePromise<api::PeerInfos>>>& peers_calls_channel() {
        return peers_calls_channel_;
    }

    Channel<api::router::PeerCall>& peer_calls_channel() {
        return peer_calls_channel_;
    }

    Channel<std::optional<EccPublicKey>>& peer_penalize_calls_channel() {
        return peer_penalize_calls_channel_;
    }

    Channel<api::router::PeerEventsCall>& peer_events_calls_channel() {
        return peer_events_calls_channel_;
    }

  private:
    Task<void> handle_peer_count_calls();
    Task<void> handle_peers_calls();
    Task<void> handle_peer_calls();
    Task<void> handle_peer_penalize_calls();
    Task<void> handle_peer_events_calls();
    Task<void> unsubscribe_peer_events_on_signal(std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal);
    Task<void> forward_peer_events();

    // PeerManagerObserver
    void on_peer_added(std::shared_ptr<rlpx::Peer> peer) override;
    void on_peer_removed(std::shared_ptr<rlpx::Peer> peer) override;
    void on_peer_connect_error(const EnodeUrl& peer_url) override;

    PeerManager& peer_manager_;

    Channel<std::shared_ptr<concurrency::AwaitablePromise<size_t>>> peer_count_calls_channel_;
    Channel<std::shared_ptr<concurrency::AwaitablePromise<api::PeerInfos>>> peers_calls_channel_;
    Channel<api::router::PeerCall> peer_calls_channel_;
    Channel<std::optional<EccPublicKey>> peer_penalize_calls_channel_;
    Channel<api::router::PeerEventsCall> peer_events_calls_channel_;

    struct Subscription {
        std::shared_ptr<Channel<api::PeerEvent>> events_channel;
        std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal;
    };

    std::list<Subscription> events_subscriptions_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;
    concurrency::TaskGroup events_unsubscription_tasks_;
    Channel<api::PeerEvent> peer_events_channel_;
};

}  // namespace silkworm::sentry
