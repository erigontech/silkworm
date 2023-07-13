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

#include <silkworm/sentry/common/enode_url.hpp>
#include <silkworm/sentry/rlpx/peer.hpp>

namespace silkworm::sentry {

struct PeerManagerObserver {
    virtual ~PeerManagerObserver() = default;
    virtual void on_peer_added(std::shared_ptr<silkworm::sentry::rlpx::Peer> peer) = 0;
    virtual void on_peer_removed(std::shared_ptr<silkworm::sentry::rlpx::Peer> peer) = 0;
    virtual void on_peer_connect_error(const EnodeUrl& peer_url) = 0;
};

}  // namespace silkworm::sentry
