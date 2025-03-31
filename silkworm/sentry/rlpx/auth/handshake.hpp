// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <absl/strings/str_cat.h>

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
        explicit DisconnectError(DisconnectReason reason)
            : std::runtime_error("rlpx::auth::Handshake: Disconnect received"),
              reason_(reason) {}
        DisconnectReason reason() const { return reason_; }

      private:
        DisconnectReason reason_;
    };

    class CapabilityMismatchError : public std::runtime_error {
      public:
        CapabilityMismatchError(
            const std::string& required_capability_desc,
            const std::string& peer_capabilities_desc)
            : std::runtime_error(absl::StrCat("rlpx::auth::Handshake: no matching required capability ",
                                              required_capability_desc, " in ", peer_capabilities_desc)) {}
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
