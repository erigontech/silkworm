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

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/socket_stream.hpp>

#include "auth_keys.hpp"

namespace silkworm::sentry::rlpx::auth {

class AuthRecipient {
  public:
    explicit AuthRecipient(EccKeyPair recipient_key_pair)
        : recipient_key_pair_(std::move(recipient_key_pair)) {}

    Task<AuthKeys> execute(SocketStream& stream);

  private:
    EccKeyPair recipient_key_pair_;
    EccKeyPair recipient_ephemeral_key_pair_;
};

}  // namespace silkworm::sentry::rlpx::auth
