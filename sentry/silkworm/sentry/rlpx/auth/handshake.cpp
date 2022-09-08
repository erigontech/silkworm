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

#include <silkworm/common/log.hpp>
#include <silkworm/sentry/common/awaitable_wait_for_one.hpp>
#include <silkworm/sentry/common/timeout.hpp>
#include <silkworm/sentry/rlpx/common/disconnect_message.hpp>
#include <silkworm/sentry/rlpx/framing/framing_cipher.hpp>

#include "auth_initiator.hpp"
#include "auth_recipient.hpp"
#include "ecies_cipher.hpp"
#include "hello_message.hpp"

namespace silkworm::sentry::rlpx::auth {

using namespace std::chrono_literals;
using namespace common::awaitable_wait_for_one;
using common::Message;

boost::asio::awaitable<AuthKeys> Handshake::auth(common::SocketStream& stream) {
    if (peer_public_key_) {
        auth::AuthInitiator auth_initiator{node_key_, peer_public_key_.value()};
        co_return (co_await auth_initiator.execute(stream));
    } else {
        auth::AuthRecipient auth_recipient{node_key_};
        co_return (co_await auth_recipient.execute(stream));
    }
}

boost::asio::awaitable<framing::MessageStream> Handshake::execute(common::SocketStream& stream) {
    auto auth_keys = co_await auth(stream);
    log::Debug() << "AuthKeys.peer_ephemeral_public_key: " << auth_keys.peer_ephemeral_public_key.hex();

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

    common::Timeout timeout(5s);

    HelloMessage hello_message{
        client_id_,
        {
            {"p2p", HelloMessage::kProtocolVersion},
            HelloMessage::Capability{required_capability_},
        },
        node_listen_port_,
        node_key_.public_key(),
    };
    co_await (message_stream.send(hello_message.to_message()) || timeout());

    Message reply_message = std::get<Message>(co_await (message_stream.receive() || timeout()));
    if (reply_message.id != HelloMessage::kId) {
        if (reply_message.id == DisconnectMessage::kId) {
            throw DisconnectError();
        } else {
            throw std::runtime_error("Handshake: unexpected RLPx message");
        }
    }

    HelloMessage hello_reply_message = HelloMessage::from_message(reply_message);
    log::Debug() << "Handshake success: peer Hello: " << hello_reply_message.client_id()
                 << " with " << hello_reply_message.capabilities_description();

    if (!hello_reply_message.contains_capability(HelloMessage::Capability{required_capability_}))
        throw std::runtime_error("Handshake: no matching required capability");

    message_stream.enable_compression();

    co_return message_stream;
}

}  // namespace silkworm::sentry::rlpx::auth
