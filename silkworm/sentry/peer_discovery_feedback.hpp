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

#include <memory>
#include <optional>
#include <utility>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/discovery/discovery.hpp>
#include <silkworm/sentry/rlpx/common/disconnect_reason.hpp>

#include "peer_manager.hpp"
#include "peer_manager_observer.hpp"

namespace silkworm::sentry {

class PeerDiscoveryFeedback : public PeerManagerObserver {
  public:
    PeerDiscoveryFeedback(const boost::asio::any_io_executor& executor, size_t max_peers)
        : peer_disconnected_events_(executor, max_peers) {}

    static Task<void> run(
        std::shared_ptr<PeerDiscoveryFeedback> self,
        PeerManager& peer_manager,
        discovery::Discovery& discovery);

  private:
    // PeerManagerObserver
    void on_peer_added(std::shared_ptr<rlpx::Peer> peer) override;
    void on_peer_removed(std::shared_ptr<rlpx::Peer> peer) override;
    void on_peer_connect_error(const EnodeUrl& peer_url) override;

    struct PeerDisconnectedEvent {
        std::optional<EccPublicKey> peer_public_key;
        std::optional<rlpx::DisconnectReason> disconnect_reason;
    };

    concurrency::Channel<PeerDisconnectedEvent> peer_disconnected_events_;
};

}  // namespace silkworm::sentry
