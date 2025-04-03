// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "multi_sentry_client.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/parallel_group_utils.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>
#include <silkworm/sentry/api/common/service.hpp>
#include <silkworm/sentry/common/atomic_value.hpp>

namespace silkworm::sentry {

using namespace boost::asio;
using namespace boost::asio::experimental;
using namespace api;

class MultiSentryClientImpl : public api::Service {
  public:
    explicit MultiSentryClientImpl(
        std::vector<std::shared_ptr<SentryClient>> clients)
        : clients_(std::move(clients)) {
    }

  private:
    Task<void> for_each_client(
        std::vector<std::shared_ptr<SentryClient>> clients,
        std::chrono::milliseconds timeout,
        std::function<Task<void>(std::shared_ptr<api::Service>)> callback) {
        using namespace concurrency::awaitable_wait_for_one;

        auto call_factory = [&clients, &callback](size_t index) -> Task<void> {
            const auto& client = clients[index];
            auto service = co_await client->service();
            co_await callback(service);
        };

        auto group_task = concurrency::generate_parallel_group_task(clients.size(), call_factory);

        try {
            co_await (std::move(group_task) || concurrency::timeout(timeout));
        } catch (const concurrency::TimeoutExpiredError&) {
        }
    }

    Task<void> for_each_client(
        std::function<Task<void>(std::shared_ptr<api::Service>)> callback) {
        using namespace std::chrono_literals;

        auto clients = this->ready_clients();
        if (clients.empty()) {
            clients = clients_;
        }

        return for_each_client(clients, /* timeout = */ 10s, std::move(callback));
    }

  public:
    // rpc SetStatus(StatusData) returns (SetStatusReply);
    Task<void> set_status(eth::StatusData status_data) override {
        co_await for_each_client([&status_data](auto service) -> Task<void> {
            co_await service->set_status(status_data);
        });
    }

    // rpc HandShake(google.protobuf.Empty) returns (HandShakeReply);
    Task<uint8_t> handshake() override {
        // handshake is not performed on the multi-client level
        SILKWORM_ASSERT(false);
        co_return 0;
    }

    // rpc NodeInfo(google.protobuf.Empty) returns(types.NodeInfoReply);
    Task<NodeInfos> node_infos() override {
        NodeInfos all_infos;
        std::mutex all_infos_mutex;

        co_await for_each_client([&all_infos, &all_infos_mutex](auto service) -> Task<void> {
            auto infos = co_await service->node_infos();

            std::scoped_lock lock(all_infos_mutex);
            all_infos.insert(all_infos.end(), infos.begin(), infos.end());
        });
        co_return all_infos;
    }

    // rpc SendMessageById(SendMessageByIdRequest) returns (SentPeers);
    Task<PeerKeys> send_message_by_id(Message message, EccPublicKey public_key) override {
        PeerKeys all_peer_keys;
        std::mutex all_peer_keys_mutex;

        co_await for_each_client([&](auto service) -> Task<void> {
            auto peer_keys = co_await service->send_message_by_id(message, public_key);

            std::scoped_lock lock(all_peer_keys_mutex);
            all_peer_keys.insert(all_peer_keys.end(), peer_keys.begin(), peer_keys.end());
        });
        co_return all_peer_keys;
    }

    // rpc SendMessageToRandomPeers(SendMessageToRandomPeersRequest) returns (SentPeers);
    Task<PeerKeys> send_message_to_random_peers(Message message, size_t max_peers) override {
        PeerKeys all_peer_keys;
        std::mutex all_peer_keys_mutex;

        co_await for_each_client([&](auto service) -> Task<void> {
            auto peer_keys = co_await service->send_message_to_random_peers(message, max_peers);

            std::scoped_lock lock(all_peer_keys_mutex);
            all_peer_keys.insert(all_peer_keys.end(), peer_keys.begin(), peer_keys.end());
        });
        co_return all_peer_keys;
    }

    // rpc SendMessageToAll(OutboundMessageData) returns (SentPeers);
    Task<PeerKeys> send_message_to_all(Message message) override {
        PeerKeys all_peer_keys;
        std::mutex all_peer_keys_mutex;

        co_await for_each_client([&](auto service) -> Task<void> {
            auto peer_keys = co_await service->send_message_to_all(message);

            std::scoped_lock lock(all_peer_keys_mutex);
            all_peer_keys.insert(all_peer_keys.end(), peer_keys.begin(), peer_keys.end());
        });
        co_return all_peer_keys;
    }

    // rpc SendMessageByMinBlock(SendMessageByMinBlockRequest) returns (SentPeers);
    Task<PeerKeys> send_message_by_min_block(Message message, size_t max_peers) override {
        PeerKeys all_peer_keys;
        std::mutex all_peer_keys_mutex;

        co_await for_each_client([&](auto service) -> Task<void> {
            auto peer_keys = co_await service->send_message_by_min_block(message, max_peers);

            std::scoped_lock lock(all_peer_keys_mutex);
            all_peer_keys.insert(all_peer_keys.end(), peer_keys.begin(), peer_keys.end());
        });
        co_return all_peer_keys;
    }

    // rpc PeerMinBlock(PeerMinBlockRequest) returns (google.protobuf.Empty);
    Task<void> peer_min_block(EccPublicKey public_key) override {
        co_await for_each_client([&public_key](auto service) -> Task<void> {
            co_await service->peer_min_block(public_key);
        });
    }

    // rpc Messages(MessagesRequest) returns (stream InboundMessage);
    Task<void> messages(
        MessageIdSet message_id_filter,
        std::function<Task<void>(MessageFromPeer)> consumer) override {
        co_await for_each_client(clients_, /* timeout = */ kInfiniteDuration, [&message_id_filter, &consumer](auto service) -> Task<void> {
            co_await service->messages(message_id_filter, consumer);
        });
    }

    // rpc Peers(google.protobuf.Empty) returns (PeersReply);
    Task<PeerInfos> peers() override {
        PeerInfos all_peers;
        std::mutex all_peers_mutex;

        co_await for_each_client([&all_peers, &all_peers_mutex](auto service) -> Task<void> {
            auto peers = co_await service->peers();

            std::scoped_lock lock(all_peers_mutex);
            all_peers.insert(all_peers.end(), peers.begin(), peers.end());
        });
        co_return all_peers;
    }

    // rpc PeerCount(PeerCountRequest) returns (PeerCountReply);
    Task<size_t> peer_count() override {
        std::atomic_size_t count = 0;
        co_await for_each_client([&count](auto service) -> Task<void> {
            count += co_await service->peer_count();
        });
        co_return count;
    }

    // rpc PeerById(PeerByIdRequest) returns (PeerByIdReply);
    Task<std::optional<PeerInfo>> peer_by_id(EccPublicKey public_key) override {
        AtomicValue<std::optional<PeerInfo>> found_peer{std::nullopt};
        co_await for_each_client([&public_key, &found_peer](auto service) -> Task<void> {
            auto peer = co_await service->peer_by_id(public_key);
            if (peer) {
                found_peer.set(peer);
            }
        });
        co_return found_peer.get();
    }

    // rpc PenalizePeer(PenalizePeerRequest) returns (google.protobuf.Empty);
    Task<void> penalize_peer(EccPublicKey public_key) override {
        co_await for_each_client([&public_key](auto service) -> Task<void> {
            co_await service->penalize_peer(public_key);
        });
    }

    // rpc PeerEvents(PeerEventsRequest) returns (stream PeerEvent);
    Task<void> peer_events(
        std::function<Task<void>(PeerEvent)> consumer) override {
        co_await for_each_client(clients_, /* timeout = */ kInfiniteDuration, [&consumer](auto service) -> Task<void> {
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
    [[maybe_unused]] int non_trivial_destructor{0};  // silent clang-tidy
}

Task<std::shared_ptr<api::Service>> MultiSentryClient::service() {
    co_return p_impl_;
}

bool MultiSentryClient::is_ready() {
    return true;
}

void MultiSentryClient::on_disconnect(std::function<Task<void>()> /*callback*/) {
}

Task<void> MultiSentryClient::reconnect() {
    co_return;
}

}  // namespace silkworm::sentry
