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

#include <optional>
#include <string>
#include <utility>

#include <silkworm/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>

#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/socket_stream.hpp>
#include <silkworm/sentry/rlpx/framing/message_stream.hpp>

#include "auth_keys.hpp"

namespace silkworm::sentry::rlpx::auth {

class Handshake {
  public:
    explicit Handshake(
        common::EccKeyPair node_key,
        std::string client_id,
        uint16_t node_listen_port,
        std::pair<std::string, uint8_t> required_capability,
        std::optional<common::EccPublicKey> peer_public_key)
        : node_key_(std::move(node_key)),
          client_id_(std::move(client_id)),
          node_listen_port_(node_listen_port),
          required_capability_(std::move(required_capability)),
          is_initiator_(peer_public_key.has_value()),
          peer_public_key_(std::move(peer_public_key)) {}

    boost::asio::awaitable<framing::MessageStream> execute(common::SocketStream& stream);

    class DisconnectError : public std::runtime_error {
      public:
        DisconnectError() : std::runtime_error("Handshake: Disconnect received") {}
    };

  private:
    boost::asio::awaitable<AuthKeys> auth(common::SocketStream& stream);

    common::EccKeyPair node_key_;
    std::string client_id_;
    uint16_t node_listen_port_;
    std::pair<std::string, uint8_t> required_capability_;
    const bool is_initiator_;
    std::optional<common::EccPublicKey> peer_public_key_;
};

}  // namespace silkworm::sentry::rlpx::auth
