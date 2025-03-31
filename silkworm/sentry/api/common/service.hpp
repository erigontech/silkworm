// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/message.hpp>
#include <silkworm/sentry/eth/status_data.hpp>

#include "message_from_peer.hpp"
#include "message_id_set.hpp"
#include "node_info.hpp"
#include "peer_event.hpp"
#include "peer_info.hpp"

namespace silkworm::sentry::api {

struct Service {
    virtual ~Service() = default;

    // rpc SetStatus(StatusData) returns (SetStatusReply);
    virtual Task<void> set_status(eth::StatusData status_data) = 0;

    // rpc HandShake(google.protobuf.Empty) returns (HandShakeReply);
    virtual Task<uint8_t> handshake() = 0;

    using NodeInfos = std::vector<NodeInfo>;

    // rpc NodeInfo(google.protobuf.Empty) returns(types.NodeInfoReply);
    virtual Task<NodeInfos> node_infos() = 0;

    using PeerKeys = std::vector<sentry::EccPublicKey>;

    // rpc SendMessageById(SendMessageByIdRequest) returns (SentPeers);
    virtual Task<PeerKeys> send_message_by_id(Message message, EccPublicKey public_key) = 0;

    // rpc SendMessageToRandomPeers(SendMessageToRandomPeersRequest) returns (SentPeers);
    virtual Task<PeerKeys> send_message_to_random_peers(Message message, size_t max_peers) = 0;

    // rpc SendMessageToAll(OutboundMessageData) returns (SentPeers);
    virtual Task<PeerKeys> send_message_to_all(Message message) = 0;

    // rpc SendMessageByMinBlock(SendMessageByMinBlockRequest) returns (SentPeers);
    virtual Task<PeerKeys> send_message_by_min_block(Message message, size_t max_peers) = 0;

    // rpc PeerMinBlock(PeerMinBlockRequest) returns (google.protobuf.Empty);
    virtual Task<void> peer_min_block(EccPublicKey public_key) = 0;

    // rpc Messages(MessagesRequest) returns (stream InboundMessage);
    virtual Task<void> messages(
        MessageIdSet message_id_filter,
        std::function<Task<void>(MessageFromPeer)> consumer) = 0;

    // rpc Peers(google.protobuf.Empty) returns (PeersReply);
    virtual Task<PeerInfos> peers() = 0;

    // rpc PeerCount(PeerCountRequest) returns (PeerCountReply);
    virtual Task<size_t> peer_count() = 0;

    // rpc PeerById(PeerByIdRequest) returns (PeerByIdReply);
    virtual Task<std::optional<PeerInfo>> peer_by_id(EccPublicKey public_key) = 0;

    // rpc PenalizePeer(PenalizePeerRequest) returns (google.protobuf.Empty);
    virtual Task<void> penalize_peer(EccPublicKey public_key) = 0;

    // rpc PeerEvents(PeerEventsRequest) returns (stream PeerEvent);
    virtual Task<void> peer_events(std::function<Task<void>(PeerEvent)> consumer) = 0;
};

}  // namespace silkworm::sentry::api
