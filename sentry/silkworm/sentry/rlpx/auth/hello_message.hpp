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

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <silkworm/common/base.hpp>
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
            : name_bytes(reinterpret_cast<const uint8_t*>(name.data()), name.size()),
              version(version1) {}

        explicit Capability(const std::pair<std::string, uint8_t>& info)
            : Capability(info.first, info.second) {}

        [[nodiscard]] std::string_view name() const {
            return {reinterpret_cast<const char*>(name_bytes.data()), name_bytes.size()};
        }

        Bytes name_bytes;
        uint8_t version{0};
    };

    HelloMessage() = default;

    HelloMessage(
        std::string_view client_id,
        std::vector<Capability> capabilities,
        uint16_t listen_port,
        const common::EccPublicKey& node_id)
        : client_id_bytes_(reinterpret_cast<const uint8_t*>(client_id.data()), client_id.size()),
          capabilities_(std::move(capabilities)),
          listen_port_(listen_port),
          node_id_bytes_(node_id.serialized()) {}

    [[nodiscard]] std::string_view client_id() const {
        return {reinterpret_cast<const char*>(client_id_bytes_.data()), client_id_bytes_.size()};
    }

    [[nodiscard]] bool contains_capability(const Capability& capability) const;

    [[nodiscard]] std::string capabilities_description();

    [[nodiscard]] uint16_t listen_port() const { return listen_port_; }

    [[nodiscard]] common::EccPublicKey node_id() const {
        return common::EccPublicKey::deserialize(node_id_bytes_);
    }

    [[nodiscard]] Bytes rlp_encode() const;
    [[nodiscard]] static HelloMessage rlp_decode(ByteView data);

    [[nodiscard]] common::Message to_message() const;
    [[nodiscard]] static HelloMessage from_message(const common::Message& message);

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
