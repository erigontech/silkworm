/*
   Copyright 2022 The Silkworm Authors

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
#include <string>

#include <silkworm/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>

#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/socket_stream.hpp>

namespace silkworm::sentry::rlpx {

class Peer {
  public:
    explicit Peer(
        common::SocketStream stream,
        common::EccKeyPair node_key,
        std::string client_id,
        uint16_t node_listen_port,
        std::optional<common::EccPublicKey> peer_public_key)
        : stream_(std::move(stream)),
          node_key_(std::move(node_key)),
          client_id_(std::move(client_id)),
          node_listen_port_(node_listen_port),
          peer_public_key_(std::move(peer_public_key)) {}

    Peer(Peer&&) = default;
    Peer& operator=(Peer&&) = default;

    boost::asio::awaitable<void> handle();

  private:
    common::SocketStream stream_;
    common::EccKeyPair node_key_;
    std::string client_id_;
    uint16_t node_listen_port_;
    std::optional<common::EccPublicKey> peer_public_key_;
};

}  // namespace silkworm::sentry::rlpx
