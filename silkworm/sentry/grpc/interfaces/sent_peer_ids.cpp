// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "sent_peer_ids.hpp"

#include "peer_id.hpp"

namespace silkworm::sentry::grpc::interfaces {

namespace proto = ::sentry;

proto::SentPeers sent_peers_ids_from_peer_keys(const std::vector<sentry::EccPublicKey>& keys) {
    proto::SentPeers result;
    for (auto& key : keys) {
        result.add_peers()->CopyFrom(peer_id_from_public_key(key));
    }
    return result;
}

std::vector<sentry::EccPublicKey> peer_keys_from_sent_peers_ids(const proto::SentPeers& peer_ids) {
    std::vector<sentry::EccPublicKey> result;
    result.reserve(static_cast<size_t>(peer_ids.peers_size()));
    for (auto& peer_id : peer_ids.peers()) {
        result.push_back(peer_public_key_from_id(peer_id));
    }
    return result;
}

}  // namespace silkworm::sentry::grpc::interfaces
