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

#include "multi_sentry_client.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <functional>
#include <mutex>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/sentry/api/api_common/service.hpp>
#include <silkworm/sentry/common/atomic_value.hpp>
#include <silkworm/sentry/common/timeout.hpp>

namespace silkworm::sentry {

using namespace boost::asio;
using namespace boost::asio::experimental;
using namespace api::api_common;

class MultiSentryClientImpl : public api::api_common::Service {
  public:
    explicit MultiSentryClientImpl(
        std::vector<std::shared_ptr<SentryClient>> clients)
        : clients_(std::move(clients)) {
    }

  private:
    awaitable<void> for_each_client(
        std::vector<std::shared_ptr<SentryClient>> clients,
        std::chrono::milliseconds timeout,
        std::function<awaitable<void>(std::shared_ptr<api::api_common::Service>)> callback) {
        using namespace concurrency::awaitable_wait_for_one;

        auto executor = co_await this_coro::executor;
        using OperationType = decltype(co_spawn(executor, ([]() -> awaitable<void> { co_return; })(), deferred));
        std::vector<OperationType> calls;

        for (auto client : clients) {
            auto call = [client, &callback]() -> awaitable<void> {
                auto service = co_await client->service();
                co_await callback(service);
            };
            calls.push_back(co_spawn(executor, call(), deferred));
        }

        auto group = make_parallel_group(std::move(calls));
        auto group_wait = group.async_wait(wait_for_one_error(), use_awaitable);

        try {
            auto results = co_await (std::move(group_wait) || common::Timeout::after(timeout));

            // std::vector<size_t> order;
            // std::vector<std::exception_ptr> exceptions;
            auto [order, exceptions] = std::get<0>(std::move(results));

            // TODO
            // detail::rethrow_exceptions(ex0, ex1, order);
        } catch (const common::Timeout::ExpiredError&) {
        }
    }

    awaitable<void> for_each_client(
        std::function<awaitable<void>(std::shared_ptr<api::api_common::Service>)> callback) {
        using namespace std::chrono_literals;

        auto clients = this->ready_clients();
        if (clients.empty()) {
            clients = clients_;
        }

        return for_each_client(clients, /* timeout = */ 10s, std::move(callback));
    }

  public:
    // rpc SetStatus(StatusData) returns (SetStatusReply);
    awaitable<void> set_status(eth::StatusData status_data) override {
        co_await for_each_client([&status_data](auto service) -> awaitable<void> {
            co_await service->set_status(status_data);
        });
    }

    // rpc HandShake(google.protobuf.Empty) returns (HandShakeReply);
    awaitable<uint8_t> handshake() override {
        // handshake is not performed on the multi-client level
        assert(false);
        co_return 0;
    }

    // rpc NodeInfo(google.protobuf.Empty) returns(types.NodeInfoReply);
    awaitable<NodeInfos> node_infos() override {
        NodeInfos all_infos;
        std::mutex all_infos_mutex;

        co_await for_each_client([&all_infos, &all_infos_mutex](auto service) -> awaitable<void> {
            auto infos = co_await service->node_infos();

            std::scoped_lock lock(all_infos_mutex);
            all_infos.insert(all_infos.end(), infos.begin(), infos.end());
        });
        co_return all_infos;
    }

    // rpc SendMessageById(SendMessageByIdRequest) returns (SentPeers);
    awaitable<PeerKeys> send_message_by_id(common::Message message, common::EccPublicKey public_key) override {
        PeerKeys all_peer_keys;
        std::mutex all_peer_keys_mutex;

        co_await for_each_client([&](auto service) -> awaitable<void> {
            auto peer_keys = co_await service->send_message_by_id(message, public_key);

            std::scoped_lock lock(all_peer_keys_mutex);
            all_peer_keys.insert(all_peer_keys.end(), peer_keys.begin(), peer_keys.end());
        });
        co_return all_peer_keys;
    }

    // rpc SendMessageToRandomPeers(SendMessageToRandomPeersRequest) returns (SentPeers);
    awaitable<PeerKeys> send_message_to_random_peers(common::Message message, size_t max_peers) override {
        PeerKeys all_peer_keys;
        std::mutex all_peer_keys_mutex;

        co_await for_each_client([&](auto service) -> awaitable<void> {
            auto peer_keys = co_await service->send_message_to_random_peers(message, max_peers);

            std::scoped_lock lock(all_peer_keys_mutex);
            all_peer_keys.insert(all_peer_keys.end(), peer_keys.begin(), peer_keys.end());
        });
        co_return all_peer_keys;
    }

    // rpc SendMessageToAll(OutboundMessageData) returns (SentPeers);
    awaitable<PeerKeys> send_message_to_all(common::Message message) override {
        PeerKeys all_peer_keys;
        std::mutex all_peer_keys_mutex;

        co_await for_each_client([&](auto service) -> awaitable<void> {
            auto peer_keys = co_await service->send_message_to_all(message);

            std::scoped_lock lock(all_peer_keys_mutex);
            all_peer_keys.insert(all_peer_keys.end(), peer_keys.begin(), peer_keys.end());
        });
        co_return all_peer_keys;
    }

    // rpc SendMessageByMinBlock(SendMessageByMinBlockRequest) returns (SentPeers);
    awaitable<PeerKeys> send_message_by_min_block(common::Message message, size_t max_peers) override {
        PeerKeys all_peer_keys;
        std::mutex all_peer_keys_mutex;

        co_await for_each_client([&](auto service) -> awaitable<void> {
            auto peer_keys = co_await service->send_message_by_min_block(message, max_peers);

            std::scoped_lock lock(all_peer_keys_mutex);
            all_peer_keys.insert(all_peer_keys.end(), peer_keys.begin(), peer_keys.end());
        });
        co_return all_peer_keys;
    }

    // rpc PeerMinBlock(PeerMinBlockRequest) returns (google.protobuf.Empty);
    awaitable<void> peer_min_block(common::EccPublicKey public_key) override {
        co_await for_each_client([&public_key](auto service) -> awaitable<void> {
            co_await service->peer_min_block(public_key);
        });
    }

    // rpc Messages(MessagesRequest) returns (stream InboundMessage);
    awaitable<void> messages(
        MessageIdSet message_id_filter,
        std::function<awaitable<void>(MessageFromPeer)> consumer) override {
        co_await for_each_client(clients_, /* timeout = */ kInfiniteDuration, [&message_id_filter, &consumer](auto service) -> awaitable<void> {
            co_await service->messages(message_id_filter, consumer);
        });
    }

    // rpc Peers(google.protobuf.Empty) returns (PeersReply);
    awaitable<PeerInfos> peers() override {
        PeerInfos all_peers;
        std::mutex all_peers_mutex;

        co_await for_each_client([&all_peers, &all_peers_mutex](auto service) -> awaitable<void> {
            auto peers = co_await service->peers();

            std::scoped_lock lock(all_peers_mutex);
            all_peers.insert(all_peers.end(), peers.begin(), peers.end());
        });
        co_return all_peers;
    }

    // rpc PeerCount(PeerCountRequest) returns (PeerCountReply);
    awaitable<size_t> peer_count() override {
        std::atomic_size_t count = 0;
        co_await for_each_client([&count](auto service) -> awaitable<void> {
            count += co_await service->peer_count();
        });
        co_return count;
    }

    // rpc PeerById(PeerByIdRequest) returns (PeerByIdReply);
    awaitable<std::optional<PeerInfo>> peer_by_id(common::EccPublicKey public_key) override {
        common::AtomicValue<std::optional<PeerInfo>> found_peer{std::nullopt};
        co_await for_each_client([&public_key, &found_peer](auto service) -> awaitable<void> {
            auto peer = co_await service->peer_by_id(public_key);
            if (peer) {
                found_peer.set(peer);
            }
        });
        co_return found_peer.get();
    }

    // rpc PenalizePeer(PenalizePeerRequest) returns (google.protobuf.Empty);
    awaitable<void> penalize_peer(common::EccPublicKey public_key) override {
        co_await for_each_client([&public_key](auto service) -> awaitable<void> {
            co_await service->penalize_peer(public_key);
        });
    }

    // rpc PeerEvents(PeerEventsRequest) returns (stream PeerEvent);
    awaitable<void> peer_events(
        std::function<awaitable<void>(PeerEvent)> consumer) override {
        co_await for_each_client(clients_, /* timeout = */ kInfiniteDuration, [&consumer](auto service) -> awaitable<void> {
            co_await service->peer_events(consumer);
        });
    }

  private:
    std::vector<std::shared_ptr<SentryClient>> ready_clients() {
        std::vector<std::shared_ptr<SentryClient>> ready_clients;
        for (auto& client : clients_) {
            if (client->is_ready()) {
                ready_clients.push_back(client);
            }
        }
        return ready_clients;
    }

    static constexpr std::chrono::milliseconds kInfiniteDuration = std::chrono::milliseconds::max();

    std::vector<std::shared_ptr<SentryClient>> clients_;
};

MultiSentryClient::MultiSentryClient(
    std::vector<std::shared_ptr<SentryClient>> clients)
    : p_impl_(std::make_shared<MultiSentryClientImpl>(std::move(clients))) {
}

MultiSentryClient::~MultiSentryClient() {
    [[maybe_unused]] int non_trivial_destructor;  // silent clang-tidy
}

awaitable<std::shared_ptr<api::api_common::Service>> MultiSentryClient::service() {
    co_return p_impl_;
}

bool MultiSentryClient::is_ready() {
    return true;
}

void MultiSentryClient::on_disconnect(std::function<awaitable<void>()> /*callback*/) {
}

awaitable<void> MultiSentryClient::reconnect() {
    co_return;
}

}  // namespace silkworm::sentry
