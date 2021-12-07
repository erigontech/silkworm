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

#include "peer_min_block.hpp"

namespace silkworm::rpc {

PeerMinBlock::PeerMinBlock(const std::string& peerId, BlockNum minBlock)
    : UnaryCall("PeerMinBlock", &sentry::Sentry::Stub::PeerMinBlock, {}) {
    request_.set_allocated_peer_id(to_H512(peerId).release());
    request_.set_min_block(minBlock);  // take ownership
}

}  // namespace silkworm::rpc