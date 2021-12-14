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

#ifndef SILKWORM_PEER_MIN_BLOCK_HPP
#define SILKWORM_PEER_MIN_BLOCK_HPP

#include <silkworm/downloader/sentry_client.hpp>

namespace silkworm::rpc {

class PeerMinBlock : public rpc::UnaryCall<sentry::Sentry, sentry::PeerMinBlockRequest, google::protobuf::Empty> {
  public:
    PeerMinBlock(const std::string& peerId, BlockNum minBlock);
};

}  // namespace silkworm::rpc

#endif  // SILKWORM_PEER_MIN_BLOCK_HPP
