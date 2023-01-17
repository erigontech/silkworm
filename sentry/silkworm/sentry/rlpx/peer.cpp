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

#include "peer.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/error.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/sentry/common/awaitable_wait_for_one.hpp>

#include "auth/handshake.hpp"

namespace silkworm::sentry::rlpx {

void Peer::start_detached(const std::shared_ptr<Peer>& peer) {
    boost::asio::co_spawn(peer->strand_, Peer::handle(peer), boost::asio::detached);
}

boost::asio::awaitable<void> Peer::handle(std::shared_ptr<Peer> peer) {
    co_await peer->handle();
}

boost::asio::awaitable<void> Peer::handle() {
    using namespace common::awaitable_wait_for_one;

    try {
        log::Debug() << "Peer::handle";

        auth::Handshake handshake{
            node_key_,
            client_id_,
            node_listen_port_,
            protocol_->capability(),
            peer_public_key_.get(),
        };
        auto [message_stream, peer_public_key] = co_await handshake.execute(stream_);
        peer_public_key_.set(peer_public_key);

        co_await message_stream.send(protocol_->first_message());
        auto first_message = co_await message_stream.receive();
        log::Debug() << "Peer::handle first_message: " << int(first_message.id);

        protocol_->handle_peer_first_message(first_message);

        co_await (send_messages(message_stream) || receive_messages(message_stream));

    } catch (const auth::Handshake::DisconnectError&) {
        // TODO: handle disconnect
        log::Debug() << "Peer::handle DisconnectError";
        co_return;
    } catch (const Protocol::IncompatiblePeerError&) {
        // TODO: handle disconnect: send reason 0x03 Useless peer
        log::Debug() << "Peer::handle IncompatiblePeerError";
        co_return;
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::asio::error::eof) {
            // TODO: handle disconnect
            log::Debug() << "Peer::handle EOF";
            co_return;
        } else if (ex.code() == boost::asio::error::connection_reset) {
            // TODO: handle disconnect
            log::Debug() << "Peer::handle connection reset";
            co_return;
        }
        log::Error() << "Peer::handle system_error: " << ex.what();
        throw;
    } catch (const std::exception& ex) {
        log::Error() << "Peer::handle exception: " << ex.what();
        throw;
    }
}

void Peer::send_message_detached(const std::shared_ptr<Peer>& peer, const common::Message& message) {
    boost::asio::co_spawn(peer->strand_, Peer::send_message(peer, message), boost::asio::detached);
}

boost::asio::awaitable<void> Peer::send_message(std::shared_ptr<Peer> peer, common::Message message) {
    co_await peer->send_message(message);
}

boost::asio::awaitable<void> Peer::send_message(common::Message message) {
    co_await send_message_channel_.send(message);
}

boost::asio::awaitable<void> Peer::send_messages(framing::MessageStream& message_stream) {
    while (true) {
        auto message = co_await send_message_channel_.receive();
        co_await message_stream.send(std::move(message));
    }
}

boost::asio::awaitable<common::Message> Peer::receive_message() {
    return receive_message_channel_.receive();
}

boost::asio::awaitable<void> Peer::receive_messages(framing::MessageStream& message_stream) {
    while (true) {
        auto message = co_await message_stream.receive();
        co_await receive_message_channel_.send(std::move(message));
    }
}

}  // namespace silkworm::sentry::rlpx
