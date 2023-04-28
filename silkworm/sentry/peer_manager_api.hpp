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

#pragma once

#include <list>
#include <memory>
#include <optional>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>

#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/infra/concurrency/event_notifier.hpp>
#include <silkworm/infra/concurrency/task_group.hpp>
#include <silkworm/sentry/api/api_common/peer_event.hpp>
#include <silkworm/sentry/api/api_common/peer_info.hpp>
#include <silkworm/sentry/api/router/peer_call.hpp>
#include <silkworm/sentry/api/router/peer_events_call.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/promise.hpp>

#include "peer_manager.hpp"
#include "rlpx/peer.hpp"

namespace silkworm::sentry {

class PeerManagerApi : public PeerManagerObserver {
  public:
    explicit PeerManagerApi(
        boost::asio::io_context& io_context,
        PeerManager& peer_manager)
        : peer_manager_(peer_manager),
          peer_count_calls_channel_(io_context),
          peers_calls_channel_(io_context),
          peer_calls_channel_(io_context),
          peer_penalize_calls_channel_(io_context),
          peer_events_calls_channel_(io_context),
          strand_(boost::asio::make_strand(io_context)),
          events_unsubscription_tasks_(strand_, 1000),
          peer_events_channel_(io_context, 1000) {}

    static boost::asio::awaitable<void> start(std::shared_ptr<PeerManagerApi> self);

    template <typename T>
    using Channel = concurrency::Channel<T>;

    Channel<std::shared_ptr<common::Promise<size_t>>>& peer_count_calls_channel() {
        return peer_count_calls_channel_;
    }

    Channel<std::shared_ptr<common::Promise<api::api_common::PeerInfos>>>& peers_calls_channel() {
        return peers_calls_channel_;
    }

    Channel<api::router::PeerCall>& peer_calls_channel() {
        return peer_calls_channel_;
    }

    Channel<std::optional<common::EccPublicKey>>& peer_penalize_calls_channel() {
        return peer_penalize_calls_channel_;
    }

    Channel<api::router::PeerEventsCall>& peer_events_calls_channel() {
        return peer_events_calls_channel_;
    }

  private:
    boost::asio::awaitable<void> handle_peer_count_calls();
    boost::asio::awaitable<void> handle_peers_calls();
    boost::asio::awaitable<void> handle_peer_calls();
    boost::asio::awaitable<void> handle_peer_penalize_calls();
    boost::asio::awaitable<void> handle_peer_events_calls();
    boost::asio::awaitable<void> unsubscribe_peer_events_on_signal(std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal);
    boost::asio::awaitable<void> forward_peer_events();

    // PeerManagerObserver
    void on_peer_added(std::shared_ptr<rlpx::Peer> peer) override;
    void on_peer_removed(std::shared_ptr<rlpx::Peer> peer) override;

    PeerManager& peer_manager_;

    Channel<std::shared_ptr<common::Promise<size_t>>> peer_count_calls_channel_;
    Channel<std::shared_ptr<common::Promise<api::api_common::PeerInfos>>> peers_calls_channel_;
    Channel<api::router::PeerCall> peer_calls_channel_;
    Channel<std::optional<common::EccPublicKey>> peer_penalize_calls_channel_;
    Channel<api::router::PeerEventsCall> peer_events_calls_channel_;

    struct Subscription {
        std::shared_ptr<Channel<api::api_common::PeerEvent>> events_channel;
        std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal;
    };

    std::list<Subscription> events_subscriptions_;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;
    concurrency::TaskGroup events_unsubscription_tasks_;
    Channel<api::api_common::PeerEvent> peer_events_channel_;
};

}  // namespace silkworm::sentry
