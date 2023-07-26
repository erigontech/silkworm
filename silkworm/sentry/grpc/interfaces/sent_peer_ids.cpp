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
