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

#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <vector>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>

#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/infra/concurrency/event_notifier.hpp>
#include <silkworm/infra/rpc/server/server_context_pool.hpp>
#include <silkworm/sentry/common/enode_url.hpp>
#include <silkworm/sentry/common/task_group.hpp>
#include <silkworm/sentry/discovery/discovery.hpp>
#include <silkworm/sentry/rlpx/client.hpp>
#include <silkworm/sentry/rlpx/peer.hpp>
#include <silkworm/sentry/rlpx/rlpx_common/disconnect_reason.hpp>
#include <silkworm/sentry/rlpx/server.hpp>

namespace silkworm::sentry {

class PeerManagerObserver;

class PeerManager {
  public:
    PeerManager(
        boost::asio::io_context& io_context,
        size_t max_peers,
        silkworm::rpc::ServerContextPool& context_pool)
        : max_peers_(max_peers),
          strand_(boost::asio::make_strand(io_context)),
          peer_tasks_(strand_, max_peers),
          drop_peer_tasks_(strand_, PeerManager::kMaxSimultaneousDropPeerTasks),
          context_pool_(context_pool),
          need_peers_notifier_(io_context),
          connect_peer_tasks_(strand_, max_peers),
          client_peer_channel_(io_context) {}

    boost::asio::awaitable<void> start(
        rlpx::Server& server,
        discovery::Discovery& discovery,
        std::function<std::unique_ptr<rlpx::Client>()> client_factory);

    using EnumeratePeersCallback = std::function<void(std::shared_ptr<rlpx::Peer>)>;

    boost::asio::awaitable<size_t> count_peers();
    boost::asio::awaitable<void> enumerate_peers(EnumeratePeersCallback callback);
    boost::asio::awaitable<void> enumerate_random_peers(size_t max_count, EnumeratePeersCallback callback);

    void add_observer(std::weak_ptr<PeerManagerObserver> observer);

  private:
    boost::asio::awaitable<void> start_in_strand(concurrency::Channel<std::shared_ptr<rlpx::Peer>>& peer_channel);
    boost::asio::awaitable<void> start_peer(std::shared_ptr<rlpx::Peer> peer);
    boost::asio::awaitable<void> wait_for_peer_handshake(std::shared_ptr<rlpx::Peer> peer);
    boost::asio::awaitable<void> drop_peer(
        std::shared_ptr<rlpx::Peer> peer,
        rlpx::rlpx_common::DisconnectReason reason);

    static constexpr size_t kMaxSimultaneousDropPeerTasks = 10;

    boost::asio::awaitable<size_t> count_peers_in_strand();
    boost::asio::awaitable<void> enumerate_peers_in_strand(EnumeratePeersCallback callback);
    boost::asio::awaitable<void> enumerate_random_peers_in_strand(size_t max_count, EnumeratePeersCallback callback);

    [[nodiscard]] std::list<std::shared_ptr<PeerManagerObserver>> observers();
    void on_peer_added(const std::shared_ptr<rlpx::Peer>& peer);
    void on_peer_removed(const std::shared_ptr<rlpx::Peer>& peer);

    static std::vector<common::EnodeUrl> peer_urls(const std::list<std::shared_ptr<rlpx::Peer>>& peers);
    boost::asio::awaitable<void> discover_peers(
        discovery::Discovery& discovery,
        std::function<std::unique_ptr<rlpx::Client>()> client_factory);
    boost::asio::awaitable<void> connect_peer(
        common::EnodeUrl peer_url,
        bool is_static_peer,
        std::unique_ptr<rlpx::Client> client);

    std::list<std::shared_ptr<rlpx::Peer>> peers_;
    std::list<std::shared_ptr<rlpx::Peer>> starting_peers_;
    size_t max_peers_;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;
    common::TaskGroup peer_tasks_;
    common::TaskGroup drop_peer_tasks_;
    size_t drop_peer_tasks_count_{0};

    std::set<common::EnodeUrl> connecting_peer_urls_;
    silkworm::rpc::ServerContextPool& context_pool_;
    concurrency::EventNotifier need_peers_notifier_;
    common::TaskGroup connect_peer_tasks_;
    concurrency::Channel<std::shared_ptr<rlpx::Peer>> client_peer_channel_;

    std::list<std::weak_ptr<PeerManagerObserver>> observers_;
    std::mutex observers_mutex_;
};

class PeerManagerObserver {
  public:
    virtual ~PeerManagerObserver() = default;
    virtual void on_peer_added(std::shared_ptr<rlpx::Peer> peer) = 0;
    virtual void on_peer_removed(std::shared_ptr<rlpx::Peer> peer) = 0;
};

}  // namespace silkworm::sentry
