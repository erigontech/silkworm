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

#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>

#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/message.hpp>
#include <silkworm/sentry/eth/status_data.hpp>

#include "message_from_peer.hpp"
#include "message_id_set.hpp"
#include "node_info.hpp"
#include "peer_event.hpp"
#include "peer_info.hpp"

namespace silkworm::sentry::api::api_common {

struct Service {
    virtual ~Service() = default;

    // rpc SetStatus(StatusData) returns (SetStatusReply);
    virtual boost::asio::awaitable<void> set_status(eth::StatusData status_data) = 0;

    // rpc HandShake(google.protobuf.Empty) returns (HandShakeReply);
    virtual boost::asio::awaitable<uint8_t> handshake() = 0;

    // rpc NodeInfo(google.protobuf.Empty) returns(types.NodeInfoReply);
    virtual boost::asio::awaitable<NodeInfo> node_info() = 0;

    using PeerKeys = std::vector<sentry::common::EccPublicKey>;

    // rpc SendMessageById(SendMessageByIdRequest) returns (SentPeers);
    virtual boost::asio::awaitable<PeerKeys> send_message_by_id(common::Message message, common::EccPublicKey public_key) = 0;

    // rpc SendMessageToRandomPeers(SendMessageToRandomPeersRequest) returns (SentPeers);
    virtual boost::asio::awaitable<PeerKeys> send_message_to_random_peers(common::Message message, size_t max_peers) = 0;

    // rpc SendMessageToAll(OutboundMessageData) returns (SentPeers);
    virtual boost::asio::awaitable<PeerKeys> send_message_to_all(common::Message message) = 0;

    // rpc SendMessageByMinBlock(SendMessageByMinBlockRequest) returns (SentPeers);
    virtual boost::asio::awaitable<PeerKeys> send_message_by_min_block(common::Message message, size_t max_peers) = 0;

    // rpc PeerMinBlock(PeerMinBlockRequest) returns (google.protobuf.Empty);
    virtual boost::asio::awaitable<void> peer_min_block(common::EccPublicKey public_key) = 0;

    // rpc Messages(MessagesRequest) returns (stream InboundMessage);
    virtual boost::asio::awaitable<void> messages(
        MessageIdSet message_id_filter,
        std::function<boost::asio::awaitable<void>(MessageFromPeer)> consumer) = 0;

    // rpc Peers(google.protobuf.Empty) returns (PeersReply);
    virtual boost::asio::awaitable<PeerInfos> peers() = 0;

    // rpc PeerCount(PeerCountRequest) returns (PeerCountReply);
    virtual boost::asio::awaitable<size_t> peer_count() = 0;

    // rpc PeerById(PeerByIdRequest) returns (PeerByIdReply);
    virtual boost::asio::awaitable<std::optional<PeerInfo>> peer_by_id(common::EccPublicKey public_key) = 0;

    // rpc PenalizePeer(PenalizePeerRequest) returns (google.protobuf.Empty);
    virtual boost::asio::awaitable<void> penalize_peer(common::EccPublicKey public_key) = 0;

    // rpc PeerEvents(PeerEventsRequest) returns (stream PeerEvent);
    virtual boost::asio::awaitable<void> peer_events(std::function<boost::asio::awaitable<void>(PeerEvent)> consumer) = 0;
};

}  // namespace silkworm::sentry::api::api_common
