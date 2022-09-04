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

#include <silkworm/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>

#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/socket_stream.hpp>

#include "auth_keys.hpp"

namespace silkworm::sentry::rlpx::auth {

class AuthInitiator {
  public:
    AuthInitiator(common::EccKeyPair initiator_key_pair, common::EccPublicKey recipient_public_key)
        : initiator_key_pair_(std::move(initiator_key_pair)),
          recipient_public_key_(std::move(recipient_public_key)) {}

    boost::asio::awaitable<AuthKeys> execute(common::SocketStream& stream);

  private:
    common::EccKeyPair initiator_key_pair_;
    common::EccPublicKey recipient_public_key_;
    common::EccKeyPair initiator_ephemeral_key_pair_;
};

}  // namespace silkworm::sentry::rlpx::auth
