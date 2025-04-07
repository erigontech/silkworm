// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/message.hpp>

namespace silkworm::sentry::rlpx::auth {

class HelloMessage {
  public:
    struct Capability {
        Capability() = default;

        Capability(
            std::string_view name,
            uint8_t version1)
            : name_bytes(string_view_to_byte_view(name)),
              version(version1) {}

        explicit Capability(const std::pair<std::string, uint8_t>& info)
            : Capability(info.first, info.second) {}

        std::string_view name() const {
            return byte_view_to_string_view(name_bytes);
        }

        std::string to_string() const;

        Bytes name_bytes;
        uint8_t version{0};
    };

    HelloMessage() = default;

    HelloMessage(
        std::string_view client_id,
        std::vector<Capability> capabilities,
        uint16_t listen_port,
        const EccPublicKey& node_id)
        : client_id_bytes_(string_view_to_byte_view(client_id)),
          capabilities_(std::move(capabilities)),
          listen_port_(listen_port),
          node_id_bytes_(node_id.serialized()) {}

    std::string_view client_id() const {
        return byte_view_to_string_view(client_id_bytes_);
    }

    const std::vector<Capability>& capabilities() const { return capabilities_; }

    bool contains_capability(const Capability& capability) const;

    std::string capabilities_to_string();

    uint16_t listen_port() const { return listen_port_; }

    EccPublicKey node_id() const {
        return EccPublicKey::deserialize(node_id_bytes_);
    }

    Bytes rlp_encode() const;
    static HelloMessage rlp_decode(ByteView data);

    Message to_message() const;
    static HelloMessage from_message(const Message& message);

    static const uint8_t kId;
    static const uint8_t kProtocolVersion;

  private:
    uint8_t protocol_version_{kProtocolVersion};
    Bytes client_id_bytes_;
    std::vector<Capability> capabilities_;
    uint16_t listen_port_{0};
    Bytes node_id_bytes_;
};

}  // namespace silkworm::sentry::rlpx::auth
