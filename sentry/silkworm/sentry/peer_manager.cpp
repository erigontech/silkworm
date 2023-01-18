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

#include <silkworm/sentry/common/awaitable_wait_for_one.hpp>
#include <silkworm/sentry/common/random.hpp>

namespace silkworm::sentry {

using namespace boost::asio;

awaitable<void> PeerManager::start(rlpx::Server& server, rlpx::Client& client) {
    using namespace common::awaitable_wait_for_one;

    auto start = start_in_strand(server.peer_channel()) || start_in_strand(client.peer_channel());
    co_await co_spawn(strand_, std::move(start), use_awaitable);
}

awaitable<void> PeerManager::start_in_strand(common::Channel<std::shared_ptr<rlpx::Peer>>& peer_channel) {
    while (true) {
        auto peer = co_await peer_channel.receive();
        peers_.push_back(peer);
        on_peer_added(peer);
        rlpx::Peer::start_detached(peer);
    }
}

awaitable<void> PeerManager::enumerate_peers(EnumeratePeersCallback callback) {
    co_await co_spawn(strand_, enumerate_peers_in_strand(callback), use_awaitable);
}

awaitable<void> PeerManager::enumerate_random_peers(size_t max_count, EnumeratePeersCallback callback) {
    co_await co_spawn(strand_, enumerate_random_peers_in_strand(max_count, callback), use_awaitable);
}

awaitable<void> PeerManager::enumerate_peers_in_strand(EnumeratePeersCallback callback) {
    for (auto& peer : peers_) {
        callback(peer);
    }
    co_return;
}

awaitable<void> PeerManager::enumerate_random_peers_in_strand(size_t max_count, EnumeratePeersCallback callback) {
    for (auto peer_ptr : common::random_list_items(peers_, max_count)) {
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

void PeerManager::on_peer_added(std::shared_ptr<rlpx::Peer> peer) {
    for (auto& observer : observers()) {
        observer->on_peer_added(std::move(peer));
    }
}

void PeerManager::on_peer_removed(std::shared_ptr<rlpx::Peer> peer) {
    for (auto& observer : observers()) {
        observer->on_peer_removed(std::move(peer));
    }
}

}  // namespace silkworm::sentry
