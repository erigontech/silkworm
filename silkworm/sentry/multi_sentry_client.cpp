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

#include <silkworm/sentry/api/api_common/service.hpp>

namespace silkworm::sentry {

using namespace boost::asio;
using namespace api::api_common;

class MultiSentryClientImpl : public api::api_common::Service {
  public:
    explicit MultiSentryClientImpl(
        std::vector<std::shared_ptr<api::api_common::SentryClient>> clients)
        : clients_(std::move(clients)) {
    }

    // rpc SetStatus(StatusData) returns (SetStatusReply);
    awaitable<void> set_status(eth::StatusData status_data) override {
        co_return;
    }

    // rpc HandShake(google.protobuf.Empty) returns (HandShakeReply);
    awaitable<uint8_t> handshake() override {
        co_return 0;
    }

    // rpc NodeInfo(google.protobuf.Empty) returns(types.NodeInfoReply);
    awaitable<NodeInfo> node_info() override {
        co_return NodeInfo{sentry::common::EnodeUrl{""}, sentry::common::EccPublicKey{Bytes{}}};
    }

    // rpc SendMessageById(SendMessageByIdRequest) returns (SentPeers);
    awaitable<PeerKeys> send_message_by_id(common::Message message, common::EccPublicKey public_key) override {
        co_return PeerKeys{};
    }

    // rpc SendMessageToRandomPeers(SendMessageToRandomPeersRequest) returns (SentPeers);
    awaitable<PeerKeys> send_message_to_random_peers(common::Message message, size_t max_peers) override {
        co_return PeerKeys{};
    }

    // rpc SendMessageToAll(OutboundMessageData) returns (SentPeers);
    awaitable<PeerKeys> send_message_to_all(common::Message message) override {
        co_return PeerKeys{};
    }

    // rpc SendMessageByMinBlock(SendMessageByMinBlockRequest) returns (SentPeers);
    awaitable<PeerKeys> send_message_by_min_block(common::Message message, size_t max_peers) override {
        co_return PeerKeys{};
    }

    // rpc PeerMinBlock(PeerMinBlockRequest) returns (google.protobuf.Empty);
    awaitable<void> peer_min_block(common::EccPublicKey public_key) override {
        co_return;
    }

    // rpc Messages(MessagesRequest) returns (stream InboundMessage);
    awaitable<void> messages(
        MessageIdSet message_id_filter,
        std::function<awaitable<void>(MessageFromPeer)> consumer) override {
        co_return;
    }

    // rpc Peers(google.protobuf.Empty) returns (PeersReply);
    awaitable<PeerInfos> peers() override {
        co_return PeerInfos{};
    }

    // rpc PeerCount(PeerCountRequest) returns (PeerCountReply);
    awaitable<size_t> peer_count() override {
        co_return 0;
    }

    // rpc PeerById(PeerByIdRequest) returns (PeerByIdReply);
    awaitable<std::optional<PeerInfo>> peer_by_id(common::EccPublicKey public_key) override {
        co_return std::nullopt;
    }

    // rpc PenalizePeer(PenalizePeerRequest) returns (google.protobuf.Empty);
    awaitable<void> penalize_peer(common::EccPublicKey public_key) override {
        co_return;
    }

    // rpc PeerEvents(PeerEventsRequest) returns (stream PeerEvent);
    awaitable<void> peer_events(
        std::function<awaitable<void>(PeerEvent)> consumer) override {
        co_return;
    }

  private:
    std::vector<std::shared_ptr<api::api_common::SentryClient>> clients_;
};

MultiSentryClient::MultiSentryClient(
    std::vector<std::shared_ptr<api::api_common::SentryClient>> clients)
    : p_impl_(std::make_shared<MultiSentryClientImpl>(std::move(clients))) {
}

MultiSentryClient::~MultiSentryClient() {
    [[maybe_unused]] int non_trivial_destructor;  // silent clang-tidy
}

awaitable<std::shared_ptr<api::api_common::Service>> MultiSentryClient::service() {
    co_return p_impl_;
}

void MultiSentryClient::on_disconnect(std::function<awaitable<void>()> /*callback*/) {
}

awaitable<void> MultiSentryClient::reconnect() {
    co_return;
}

}  // namespace silkworm::sentry
