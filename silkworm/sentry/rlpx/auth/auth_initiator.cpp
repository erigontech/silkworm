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

#include "auth_initiator.hpp"

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>

#include "auth_ack_message.hpp"
#include "auth_message.hpp"

namespace silkworm::sentry::rlpx::auth {

using namespace std::chrono_literals;
using namespace concurrency::awaitable_wait_for_one;

Task<AuthKeys> AuthInitiator::execute(SocketStream& stream) {
    AuthMessage auth_message{initiator_key_pair_, recipient_public_key_, initiator_ephemeral_key_pair_};
    Bytes auth_data = auth_message.serialize();
    co_await (stream.send(auth_data) || concurrency::timeout(5s));

    Bytes auth_ack_data_raw;
    auto auth_ack_data = std::get<ByteView>(co_await (stream.receive_size_and_data(auth_ack_data_raw) || concurrency::timeout(5s)));
    AuthAckMessage auth_ack_message{auth_ack_data, initiator_key_pair_};

    co_return AuthKeys{
        recipient_public_key_,
        auth_ack_message.ephemeral_public_key(),
        initiator_ephemeral_key_pair_,
        Bytes{auth_message.nonce()},
        Bytes{auth_ack_message.nonce()},
        std::move(auth_data),
        std::move(auth_ack_data_raw),
    };
}

}  // namespace silkworm::sentry::rlpx::auth
