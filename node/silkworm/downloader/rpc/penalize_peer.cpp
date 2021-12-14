/*
   Copyright 2021 The Silkworm Authors

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

#include "penalize_peer.hpp"

namespace silkworm::rpc {

PenalizePeer::PenalizePeer(const std::string& peerId, Penalty penalty)
    : UnaryCall("PenalizePeer", &sentry::Sentry::Stub::PenalizePeer, {}) {
    request_.set_allocated_peer_id(to_H512(peerId).release());

    sentry::PenaltyKind raw_penalty = static_cast<sentry::PenaltyKind>(penalty);
    request_.set_penalty(raw_penalty);
}

}  // namespace silkworm::rpc