// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "auth_recipient.hpp"

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>

#include "auth_ack_message.hpp"
#include "auth_message.hpp"

namespace silkworm::sentry::rlpx::auth {

using namespace std::chrono_literals;
using namespace concurrency::awaitable_wait_for_one;

Task<AuthKeys> AuthRecipient::execute(SocketStream& stream) {
    Bytes auth_data_raw;
    auto auth_data = std::get<ByteView>(co_await (stream.receive_size_and_data(auth_data_raw) || concurrency::timeout(5s)));
    AuthMessage auth_message{auth_data, recipient_key_pair_};

    AuthAckMessage auth_ack_message{
        auth_message.initiator_public_key(),
        recipient_ephemeral_key_pair_.public_key(),
    };
    Bytes auth_ack_data = auth_ack_message.serialize();
    co_await (stream.send(auth_ack_data) || concurrency::timeout(5s));

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
