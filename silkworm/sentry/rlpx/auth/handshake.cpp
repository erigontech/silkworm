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

#include "handshake.hpp"

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>
#include <silkworm/sentry/rlpx/common/disconnect_message.hpp>
#include <silkworm/sentry/rlpx/framing/framing_cipher.hpp>

#include "auth_initiator.hpp"
#include "auth_recipient.hpp"
#include "ecies_cipher.hpp"

namespace silkworm::sentry::rlpx::auth {

using namespace std::chrono_literals;
using namespace concurrency::awaitable_wait_for_one;

Task<AuthKeys> Handshake::auth(SocketStream& stream) {
    if (peer_public_key_) {
        auth::AuthInitiator auth_initiator{node_key_, peer_public_key_.value()};
        co_return (co_await auth_initiator.execute(stream));
    } else {
        auth::AuthRecipient auth_recipient{node_key_};
        co_return (co_await auth_recipient.execute(stream));
    }
}

Task<Handshake::HandshakeResult> Handshake::execute(SocketStream& stream) {
    auto auth_keys = co_await auth(stream);
    SILK_TRACE_M("sentry") << "rlpx::auth::Handshake AuthKeys.peer_ephemeral_public_key: " << auth_keys.peer_ephemeral_public_key.hex();

    framing::FramingCipher framing_cipher{
        framing::FramingCipher::KeyMaterial{
            EciesCipher::compute_shared_secret(
                auth_keys.peer_ephemeral_public_key,
                auth_keys.ephemeral_key_pair.private_key()),
            is_initiator_,
            auth_keys.initiator_nonce,
            auth_keys.recipient_nonce,
            auth_keys.initiator_first_message_data,
            auth_keys.recipient_first_message_data,
        }};

    framing::MessageStream message_stream{std::move(framing_cipher), stream};

    HelloMessage hello_message{
        client_id_,
        {
            {"p2p", HelloMessage::kProtocolVersion},
            HelloMessage::Capability{required_capability_},
        },
        node_listen_port_,
        node_key_.public_key(),
    };
    co_await (message_stream.send(hello_message.to_message()) || concurrency::timeout(5s));

    Message reply_message = std::get<Message>(co_await (message_stream.receive() || concurrency::timeout(5s)));
    if (reply_message.id != HelloMessage::kId) {
        if (reply_message.id == DisconnectMessage::kId) {
            auto disconnect_message = DisconnectMessage::from_message(reply_message);
            throw DisconnectError(disconnect_message.reason);
        }
        throw std::runtime_error("rlpx::auth::Handshake: unexpected RLPx message");
    }

    HelloMessage hello_reply_message = HelloMessage::from_message(reply_message);

    HelloMessage::Capability required_capability{required_capability_};
    if (!hello_reply_message.contains_capability(required_capability)) {
        throw CapabilityMismatchError(required_capability.to_string(), hello_reply_message.capabilities_to_string());
    }

    SILK_DEBUG_M("sentry") << "rlpx::auth::Handshake success: peer Hello: " << hello_reply_message.client_id()
                           << " with " << hello_reply_message.capabilities_to_string();

    message_stream.enable_compression();

    co_return Handshake::HandshakeResult{
        std::move(message_stream),
        std::move(auth_keys.peer_public_key),
        std::move(hello_reply_message),
    };
}

}  // namespace silkworm::sentry::rlpx::auth
