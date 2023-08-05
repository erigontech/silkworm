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
#include <stdexcept>
#include <string>
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/socket_stream.hpp>
#include <silkworm/sentry/rlpx/common/disconnect_reason.hpp>
#include <silkworm/sentry/rlpx/framing/message_stream.hpp>

#include "auth_keys.hpp"
#include "hello_message.hpp"

namespace silkworm::sentry::rlpx::auth {

class Handshake {
  public:
    explicit Handshake(
        EccKeyPair node_key,
        std::string client_id,
        uint16_t node_listen_port,
        std::pair<std::string, uint8_t> required_capability,
        std::optional<EccPublicKey> peer_public_key)
        : node_key_(std::move(node_key)),
          client_id_(std::move(client_id)),
          node_listen_port_(node_listen_port),
          required_capability_(std::move(required_capability)),
          is_initiator_(peer_public_key.has_value()),
          peer_public_key_(std::move(peer_public_key)) {}

    struct HandshakeResult {
        framing::MessageStream message_stream;
        EccPublicKey peer_public_key;
        HelloMessage hello_reply_message;
    };

    Task<HandshakeResult> execute(SocketStream& stream);

    class DisconnectError : public std::runtime_error {
      public:
        DisconnectError(DisconnectReason reason)
            : std::runtime_error("rlpx::auth::Handshake: Disconnect received"),
              reason_(reason) {}
        [[nodiscard]] DisconnectReason reason() const { return reason_; }

      private:
        DisconnectReason reason_;
    };

    class CapabilityMismatchError : public std::runtime_error {
      public:
        CapabilityMismatchError(
            std::string required_capability_desc,
            std::string peer_capabilities_desc)
            : std::runtime_error("rlpx::auth::Handshake: no matching required capability " + required_capability_desc + " in " + peer_capabilities_desc) {}
    };

  private:
    Task<AuthKeys> auth(SocketStream& stream);

    EccKeyPair node_key_;
    std::string client_id_;
    uint16_t node_listen_port_;
    std::pair<std::string, uint8_t> required_capability_;
    const bool is_initiator_;
    std::optional<EccPublicKey> peer_public_key_;
};

}  // namespace silkworm::sentry::rlpx::auth
