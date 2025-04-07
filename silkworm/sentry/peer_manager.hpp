// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/infra/concurrency/event_notifier.hpp>
#include <silkworm/infra/concurrency/executor_pool.hpp>
#include <silkworm/infra/concurrency/task_group.hpp>
#include <silkworm/sentry/common/enode_url.hpp>
#include <silkworm/sentry/discovery/discovery.hpp>
#include <silkworm/sentry/rlpx/client.hpp>
#include <silkworm/sentry/rlpx/common/disconnect_reason.hpp>
#include <silkworm/sentry/rlpx/peer.hpp>
#include <silkworm/sentry/rlpx/protocol.hpp>
#include <silkworm/sentry/rlpx/server.hpp>

namespace silkworm::sentry {

struct PeerManagerObserver;

class PeerManager {
  public:
    PeerManager(
        const boost::asio::any_io_executor& executor,
        size_t max_peers,
        concurrency::ExecutorPool& executor_pool)
        : max_peers_(max_peers),
          strand_(boost::asio::make_strand(executor)),
          peer_tasks_(strand_, max_peers),
          drop_peer_tasks_(strand_, PeerManager::kMaxSimultaneousDropPeerTasks),
          executor_pool_(executor_pool),
          need_peers_notifier_(executor),
          connect_peer_tasks_(strand_, max_peers),
          client_peer_channel_(executor) {}

    Task<void> run(
        rlpx::Server& server,
        discovery::Discovery& discovery,
        std::unique_ptr<rlpx::Protocol> protocol,
        std::function<std::unique_ptr<rlpx::Client>()> client_factory);

    using EnumeratePeersCallback = std::function<void(std::shared_ptr<rlpx::Peer>)>;

    Task<size_t> count_peers();
    Task<void> enumerate_peers(EnumeratePeersCallback callback);
    Task<void> enumerate_random_peers(size_t max_count, EnumeratePeersCallback callback);

    void add_observer(std::weak_ptr<PeerManagerObserver> observer);

  private:
    Task<void> run_in_strand(concurrency::Channel<std::shared_ptr<rlpx::Peer>>& peer_channel);
    Task<void> run_peer(std::shared_ptr<rlpx::Peer> peer);
    Task<void> wait_for_peer_handshake(std::shared_ptr<rlpx::Peer> peer);
    Task<void> drop_peer(
        std::shared_ptr<rlpx::Peer> peer,
        rlpx::DisconnectReason reason);

    static constexpr size_t kMaxSimultaneousDropPeerTasks = 10;

    Task<size_t> count_peers_in_strand();
    Task<void> enumerate_peers_in_strand(EnumeratePeersCallback callback);
    Task<void> enumerate_random_peers_in_strand(size_t max_count, EnumeratePeersCallback callback);

    std::list<std::shared_ptr<PeerManagerObserver>> observers();
    void on_peer_added(const std::shared_ptr<rlpx::Peer>& peer);
    void on_peer_removed(const std::shared_ptr<rlpx::Peer>& peer);
    void on_peer_connect_error(const EnodeUrl& peer_url);

    static std::vector<EnodeUrl> peer_urls(const std::list<std::shared_ptr<rlpx::Peer>>& peers);
    Task<void> discover_peers(
        discovery::Discovery& discovery,
        std::unique_ptr<rlpx::Protocol> protocol,
        std::function<std::unique_ptr<rlpx::Client>()> client_factory);
    Task<void> connect_peer(
        EnodeUrl peer_url,
        bool is_static_peer,
        std::unique_ptr<rlpx::Client> client);

    std::list<std::shared_ptr<rlpx::Peer>> peers_;
    std::list<std::shared_ptr<rlpx::Peer>> handshaking_peers_;
    size_t max_peers_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;
    concurrency::TaskGroup peer_tasks_;
    concurrency::TaskGroup drop_peer_tasks_;
    size_t drop_peer_tasks_count_{0};

    std::set<EnodeUrl> connecting_peer_urls_;
    concurrency::ExecutorPool& executor_pool_;
    concurrency::EventNotifier need_peers_notifier_;
    concurrency::TaskGroup connect_peer_tasks_;
    concurrency::Channel<std::shared_ptr<rlpx::Peer>> client_peer_channel_;

    std::list<std::weak_ptr<PeerManagerObserver>> observers_;
    std::mutex observers_mutex_;
};

}  // namespace silkworm::sentry
