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
#include <silkworm/concurrency/coroutine.hpp>
#include <boost/asio/awaitable.hpp>
#include <silkworm/sentry/common/socket_stream.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include "auth_session.hpp"

namespace silkworm::sentry::rlpx::auth {

class Handshake {
  public:
    explicit Handshake(
        common::EccKeyPair node_key,
        std::optional<common::EccPublicKey> peer_public_key)
        : node_key_(std::move(node_key)),
          peer_public_key_(std::move(peer_public_key)) {}

    boost::asio::awaitable<void> execute(common::SocketStream& stream);

  private:
    boost::asio::awaitable<AuthSession> auth(common::SocketStream& stream);

    common::EccKeyPair node_key_;
    std::optional<common::EccPublicKey> peer_public_key_;
};

}  // namespace silkworm::sentry::rlpx::auth
