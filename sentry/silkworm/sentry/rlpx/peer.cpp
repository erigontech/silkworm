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
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/channel_error.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>
#include <gsl/util>

#include <silkworm/common/log.hpp>
#include <silkworm/sentry/common/awaitable_wait_for_all.hpp>

#include "auth/handshake.hpp"

namespace silkworm::sentry::rlpx {

Peer::~Peer() {
    log::Debug() << "silkworm::sentry::rlpx::Peer::~Peer";
}

boost::asio::awaitable<void> Peer::start(const std::shared_ptr<Peer>& peer) {
    using namespace common::awaitable_wait_for_all;

    auto start = Peer::handle(peer) && Peer::send_message_tasks_wait(peer);
    return boost::asio::co_spawn(peer->strand_, std::move(start), boost::asio::use_awaitable);
}

boost::asio::awaitable<void> Peer::handle(std::shared_ptr<Peer> peer) {
    co_await peer->handle();
}

boost::asio::awaitable<void> Peer::handle() {
    using namespace common::awaitable_wait_for_all;

    auto _ = gsl::finally([this] { this->close(); });

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

        co_await (send_messages(message_stream) && receive_messages(message_stream));

    } catch (const auth::Handshake::DisconnectError&) {
        log::Debug() << "Peer::handle DisconnectError";
        co_return;
    } catch (const Protocol::IncompatiblePeerError&) {
        log::Debug() << "Peer::handle IncompatiblePeerError";
        co_return;
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::asio::error::eof) {
            log::Debug() << "Peer::handle EOF";
            co_return;
        } else if (ex.code() == boost::asio::error::connection_reset) {
            log::Debug() << "Peer::handle connection reset";
            co_return;
        } else if (ex.code() == boost::asio::error::broken_pipe) {
            log::Debug() << "Peer::handle broken pipe";
            co_return;
        } else if (ex.code() == boost::system::errc::operation_canceled) {
            log::Debug() << "Peer::handle cancelled";
            co_return;
        }
        log::Error() << "Peer::handle system_error: " << ex.what();
        throw;
    } catch (const std::exception& ex) {
        log::Error() << "Peer::handle exception: " << ex.what();
        throw;
    }
}

void Peer::close() {
    try {
        send_message_channel_.close();
        receive_message_channel_.close();
    } catch (const std::exception& ex) {
        log::Warning() << "Peer::close exception: " << ex.what();
    }
}

void Peer::post_message(const std::shared_ptr<Peer>& peer, const common::Message& message) {
    peer->send_message_tasks_.spawn(peer->strand_, Peer::send_message(peer, message));
}

boost::asio::awaitable<void> Peer::send_message_tasks_wait(std::shared_ptr<Peer> self) {
    co_await self->send_message_tasks_.wait();
}

boost::asio::awaitable<void> Peer::send_message(std::shared_ptr<Peer> peer, common::Message message) {
    try {
        co_await peer->send_message(std::move(message));
    } catch (const DisconnectedError& ex) {
        log::Debug() << "Peer::send_message: " << ex.what();
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled) {
            log::Debug() << "Peer::send_message cancelled";
            co_return;
        }
        log::Error() << "Peer::send_message system_error: " << ex.what();
        throw;
    } catch (const std::exception& ex) {
        log::Error() << "Peer::send_message exception: " << ex.what();
        throw;
    }
}

boost::asio::awaitable<void> Peer::send_message(common::Message message) {
    try {
        co_await send_message_channel_.send(std::move(message));
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::asio::experimental::error::channel_closed)
            throw DisconnectedError();
        throw;
    }
}

boost::asio::awaitable<void> Peer::send_messages(framing::MessageStream& message_stream) {
    // loop until message_stream exception
    while (true) {
        auto message = co_await send_message_channel_.receive();
        co_await message_stream.send(std::move(message));
    }
}

boost::asio::awaitable<common::Message> Peer::receive_message() {
    try {
        co_return (co_await receive_message_channel_.receive());
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::asio::experimental::error::channel_closed)
            throw DisconnectedError();
        throw;
    }
}

boost::asio::awaitable<void> Peer::receive_messages(framing::MessageStream& message_stream) {
    // loop until message_stream exception
    while (true) {
        auto message = co_await message_stream.receive();
        co_await receive_message_channel_.send(std::move(message));
    }
}

}  // namespace silkworm::sentry::rlpx
