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

#include "peer_manager.hpp"

#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>
#include <gsl/util>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/infra/concurrency/co_spawn_sw.hpp>
#include <silkworm/sentry/common/random.hpp>
#include <silkworm/sentry/common/sleep.hpp>

#include "peer_manager_observer.hpp"

namespace silkworm::sentry {

using namespace boost::asio;

Task<void> PeerManager::start(
    rlpx::Server& server,
    discovery::Discovery& discovery,
    std::function<std::unique_ptr<rlpx::Client>()> client_factory) {
    using namespace concurrency::awaitable_wait_for_all;

    need_peers_notifier_.notify();

    auto start =
        start_in_strand(server.peer_channel()) &&
        start_in_strand(client_peer_channel_) &&
        discover_peers(discovery, client_factory) &&
        connect_peer_tasks_.wait() &&
        drop_peer_tasks_.wait() &&
        peer_tasks_.wait();
    co_await concurrency::co_spawn_sw(strand_, std::move(start), use_awaitable);
}

Task<void> PeerManager::start_in_strand(concurrency::Channel<std::shared_ptr<rlpx::Peer>>& peer_channel) {
    // loop until receive() throws a cancelled exception
    while (true) {
        auto peer = co_await peer_channel.receive();

        if (peers_.size() + handshaking_peers_.size() >= max_peers_) {
            if (drop_peer_tasks_count_ < kMaxSimultaneousDropPeerTasks) {
                drop_peer_tasks_count_++;
                drop_peer_tasks_.spawn(strand_, drop_peer(peer, rlpx::DisconnectReason::TooManyPeers));
            } else {
                log::Warning("sentry") << "PeerManager::start_in_strand too many extra peers to disconnect gracefully, dropping a peer on the floor";
            }
            continue;
        }

        handshaking_peers_.push_back(peer);
        peer_tasks_.spawn(strand_, start_peer(peer));
    }
}

Task<void> PeerManager::start_peer(std::shared_ptr<rlpx::Peer> peer) {
    using namespace concurrency::awaitable_wait_for_all;

    try {
        co_await (rlpx::Peer::start(peer) && wait_for_peer_handshake(peer));
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled) {
            log::Debug("sentry") << "PeerManager::start_peer Peer::start cancelled";
        } else {
            log::Error("sentry") << "PeerManager::start_peer Peer::start system_error: " << ex.what();
        }
    } catch (const std::exception& ex) {
        log::Error("sentry") << "PeerManager::start_peer Peer::start exception: " << ex.what();
    }

    handshaking_peers_.remove(peer);
    if (peers_.remove(peer)) {
        on_peer_removed(peer);
    }

    need_peers_notifier_.notify();
}

Task<void> PeerManager::wait_for_peer_handshake(std::shared_ptr<rlpx::Peer> peer) {
    bool ok = co_await rlpx::Peer::wait_for_handshake(peer);
    if (handshaking_peers_.remove(peer) && ok) {
        peers_.push_back(peer);
        on_peer_added(peer);
    }
}

Task<void> PeerManager::drop_peer(
    std::shared_ptr<rlpx::Peer> peer,
    rlpx::DisconnectReason reason) {
    auto _ = gsl::finally([this] { this->drop_peer_tasks_count_--; });

    try {
        co_await rlpx::Peer::drop(peer, reason);
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled) {
            log::Debug("sentry") << "PeerManager::drop_peer Peer::drop cancelled";
        } else {
            log::Error("sentry") << "PeerManager::drop_peer Peer::drop system_error: " << ex.what();
        }
    } catch (const std::exception& ex) {
        log::Error("sentry") << "PeerManager::drop_peer Peer::drop exception: " << ex.what();
    }
}

Task<size_t> PeerManager::count_peers() {
    co_return (co_await concurrency::co_spawn_sw(strand_, count_peers_in_strand(), use_awaitable));
}

Task<void> PeerManager::enumerate_peers(EnumeratePeersCallback callback) {
    co_await concurrency::co_spawn_sw(strand_, enumerate_peers_in_strand(callback), use_awaitable);
}

Task<void> PeerManager::enumerate_random_peers(size_t max_count, EnumeratePeersCallback callback) {
    co_await concurrency::co_spawn_sw(strand_, enumerate_random_peers_in_strand(max_count, callback), use_awaitable);
}

Task<size_t> PeerManager::count_peers_in_strand() {
    co_return peers_.size();
}

Task<void> PeerManager::enumerate_peers_in_strand(EnumeratePeersCallback callback) {
    for (auto& peer : peers_) {
        callback(peer);
    }
    co_return;
}

Task<void> PeerManager::enumerate_random_peers_in_strand(size_t max_count, EnumeratePeersCallback callback) {
    for (auto peer_ptr : random_list_items(peers_, max_count)) {
        callback(*peer_ptr);
    }
    co_return;
}

void PeerManager::add_observer(std::weak_ptr<PeerManagerObserver> observer) {
    std::scoped_lock lock(observers_mutex_);
    observers_.push_back(std::move(observer));
}

[[nodiscard]] std::list<std::shared_ptr<PeerManagerObserver>> PeerManager::observers() {
    std::scoped_lock lock(observers_mutex_);
    std::list<std::shared_ptr<PeerManagerObserver>> observers;
    for (auto& weak_observer : observers_) {
        auto observer = weak_observer.lock();
        if (observer) {
            observers.push_back(observer);
        }
    }
    return observers;
}

void PeerManager::on_peer_added(const std::shared_ptr<rlpx::Peer>& peer) {
    for (auto& observer : observers()) {
        observer->on_peer_added(peer);
    }
}

void PeerManager::on_peer_removed(const std::shared_ptr<rlpx::Peer>& peer) {
    for (auto& observer : observers()) {
        observer->on_peer_removed(peer);
    }
}

void PeerManager::on_peer_connect_error(const EnodeUrl& peer_url) {
    for (auto& observer : observers()) {
        observer->on_peer_connect_error(peer_url);
    }
}

std::vector<EnodeUrl> PeerManager::peer_urls(const std::list<std::shared_ptr<rlpx::Peer>>& peers) {
    std::vector<EnodeUrl> urls;
    for (auto& peer : peers) {
        auto url_opt = peer->url();
        if (url_opt) {
            urls.push_back(url_opt.value());
        }
    }
    return urls;
}

Task<void> PeerManager::discover_peers(
    discovery::Discovery& discovery,
    std::function<std::unique_ptr<rlpx::Client>()> client_factory) {
    using namespace std::chrono_literals;

    // loop until a cancelled exception
    while (true) {
        size_t ongoing_peers_count = peers_.size() + handshaking_peers_.size() + connecting_peer_urls_.size();
        // when full wait until someone drops
        if (ongoing_peers_count >= max_peers_) {
            co_await need_peers_notifier_.wait();
            continue;
        }
        size_t needed_count = max_peers_ - ongoing_peers_count;

        auto ongoing_peers_urls = peer_urls(peers_);
        auto handshaking_peer_urls = peer_urls(handshaking_peers_);
        ongoing_peers_urls.insert(ongoing_peers_urls.end(), handshaking_peer_urls.begin(), handshaking_peer_urls.end());
        ongoing_peers_urls.insert(ongoing_peers_urls.end(), connecting_peer_urls_.begin(), connecting_peer_urls_.end());

        std::vector<EnodeUrl> discovered_peer_urls = co_await discovery.request_peer_urls(needed_count, ongoing_peers_urls);

        for (auto& peer_url : discovered_peer_urls) {
            connecting_peer_urls_.insert(peer_url);
            bool is_static_peer = discovery.is_static_peer_url(peer_url);
            connect_peer_tasks_.spawn(strand_, connect_peer(peer_url, is_static_peer, client_factory()));
        }

        // if nothing new retry after a delay
        if (discovered_peer_urls.empty()) {
            co_await sleep(10s);
        }
    }
}

Task<void> PeerManager::connect_peer(EnodeUrl peer_url, bool is_static_peer, std::unique_ptr<rlpx::Client> client) {
    auto _ = gsl::finally([this, peer_url] { this->connecting_peer_urls_.erase(peer_url); });

    try {
        auto& client_context = context_pool_.next_io_context();
        auto peer1 = co_await concurrency::co_spawn_sw(client_context, client->connect(peer_url, is_static_peer), use_awaitable);
        auto peer = std::shared_ptr(std::move(peer1));
        co_await client_peer_channel_.send(peer);
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled) {
            log::Debug("sentry") << "PeerManager::connect_peer cancelled";
        } else {
            log::Debug("sentry") << "PeerManager::connect_peer failed to connect"
                                 << " to " << peer_url.to_string()
                                 << " due to exception: " << ex.what();
            on_peer_connect_error(peer_url);
            need_peers_notifier_.notify();
        }
    } catch (const std::exception& ex) {
        log::Error("sentry") << "PeerManager::connect_peer exception: " << ex.what();
        need_peers_notifier_.notify();
    }
}

}  // namespace silkworm::sentry
