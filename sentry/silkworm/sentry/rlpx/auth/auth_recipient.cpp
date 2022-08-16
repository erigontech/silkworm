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

#include "auth_recipient.hpp"

#include <silkworm/common/base.hpp>
#include <silkworm/sentry/common/awaitable_wait_for_one.hpp>
#include <silkworm/sentry/common/timeout.hpp>

#include "auth_ack_message.hpp"
#include "auth_message.hpp"

namespace silkworm::sentry::rlpx::auth {

using namespace std::chrono_literals;
using namespace common::awaitable_wait_for_one;

boost::asio::awaitable<AuthKeys> AuthRecipient::execute(common::SocketStream& stream) {
    common::Timeout timeout(5s);

    Bytes auth_data_raw;
    auto auth_data = std::get<ByteView>(co_await (stream.receive_size_and_data(auth_data_raw) || timeout()));
    AuthMessage auth_message{auth_data, recipient_key_pair_};

    AuthAckMessage auth_ack_message{
        auth_message.initiator_public_key(),
        recipient_ephemeral_key_pair_.public_key(),
    };
    Bytes auth_ack_data = auth_ack_message.serialize();
    co_await (stream.send(auth_ack_data) || timeout());

    co_return AuthKeys{
        auth_message.initiator_public_key(),
        auth_message.ephemeral_public_key(),
        recipient_ephemeral_key_pair_,
        Bytes{auth_message.nonce()},
        Bytes{auth_ack_message.nonce()},
        std::move(auth_data_raw),
        std::move(auth_ack_data),
    };
}

}  // namespace silkworm::sentry::rlpx::auth
