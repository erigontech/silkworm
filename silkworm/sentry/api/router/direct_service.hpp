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

#include <silkworm/sentry/api/common/service.hpp>

#include "service_router.hpp"

namespace silkworm::sentry::api::router {

class DirectService : public Service {
  public:
    explicit DirectService(ServiceRouter router)
        : router_(std::move(router)) {}
    ~DirectService() override = default;

    Task<void> set_status(eth::StatusData status_data) override;
    Task<uint8_t> handshake() override;
    Task<NodeInfos> node_infos() override;

    Task<PeerKeys> send_message_by_id(Message message, EccPublicKey public_key) override;
    Task<PeerKeys> send_message_to_random_peers(Message message, size_t max_peers) override;
    Task<PeerKeys> send_message_to_all(Message message) override;
    Task<PeerKeys> send_message_by_min_block(Message message, size_t max_peers) override;
    Task<void> peer_min_block(EccPublicKey public_key) override;
    Task<void> messages(
        MessageIdSet message_id_filter,
        std::function<Task<void>(MessageFromPeer)> consumer) override;

    Task<PeerInfos> peers() override;
    Task<size_t> peer_count() override;
    Task<std::optional<PeerInfo>> peer_by_id(EccPublicKey public_key) override;
    Task<void> penalize_peer(EccPublicKey public_key) override;
    Task<void> peer_events(std::function<Task<void>(PeerEvent)> consumer) override;

  private:
    ServiceRouter router_;
};

}  // namespace silkworm::sentry::api::router
