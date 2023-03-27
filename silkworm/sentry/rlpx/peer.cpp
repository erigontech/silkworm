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

#include <chrono>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>
#include <gsl/util>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/sentry/common/awaitable_wait_for_all.hpp>
#include <silkworm/sentry/common/awaitable_wait_for_one.hpp>
#include <silkworm/sentry/common/sleep.hpp>
#include <silkworm/sentry/common/timeout.hpp>

#include "auth/handshake.hpp"
#include "ping_message.hpp"
#include "rlpx_common/disconnect_message.hpp"

namespace silkworm::sentry::rlpx {

using namespace std::chrono_literals;
using namespace boost::asio;
using namespace rlpx_common;

Peer::Peer(
    any_io_executor&& executor,
    common::SocketStream stream,
    common::EccKeyPair node_key,
    std::string client_id,
    uint16_t node_listen_port,
    std::unique_ptr<Protocol> protocol,
    std::optional<common::EnodeUrl> url,
    std::optional<common::EccPublicKey> peer_public_key,
    bool is_inbound,
    bool is_static)
    : stream_(std::move(stream)),
      node_key_(std::move(node_key)),
      client_id_(std::move(client_id)),
      node_listen_port_(node_listen_port),
      protocol_(std::move(protocol)),
      url_(std::move(url)),
      peer_public_key_(std::move(peer_public_key)),
      is_inbound_(is_inbound),
      is_static_(is_static),
      handshake_promise_(executor),
      strand_(make_strand(executor)),
      send_message_tasks_(strand_, 1000),
      send_message_channel_(executor),
      receive_message_channel_(executor),
      pong_channel_(executor) {
}

Peer::~Peer() {
    log::Debug() << "silkworm::sentry::rlpx::Peer::~Peer";
}

awaitable<void> Peer::start(std::shared_ptr<Peer> peer) {
    using namespace common::awaitable_wait_for_one;

    auto start = Peer::handle(peer) || Peer::send_message_tasks_wait(peer);
    co_await co_spawn(peer->strand_, std::move(start), use_awaitable);
}

static bool is_fatal_network_error(const boost::system::system_error& ex) {
    auto code = ex.code();
    return (code == boost::asio::error::eof) ||
           (code == boost::asio::error::connection_reset) ||
           (code == boost::asio::error::broken_pipe);
}

static const std::chrono::milliseconds kPeerDisconnectTimeout = 2s;
static const std::chrono::milliseconds kPeerPingInterval = 15s;

class PingTimeoutError : public std::runtime_error {
  public:
    PingTimeoutError() : std::runtime_error("Peer ping timed out") {}
};

awaitable<void> Peer::handle(std::shared_ptr<Peer> peer) {
    co_await peer->handle();
}

awaitable<void> Peer::handle() {
    using namespace common::awaitable_wait_for_all;
    using namespace common::awaitable_wait_for_one;

    log::Debug() << "Peer::handle";
    auto _ = gsl::finally([this] {
        this->handshake_promise_.set_value(false);
        this->close();
    });

    try {
        auto message_stream = co_await handshake();

        co_await message_stream.send(protocol_->first_message());
        auto first_message = co_await message_stream.receive();
        log::Debug() << "Peer::handle first_message: " << int(first_message.id);

        bool is_incompatible = false;
        try {
            protocol_->handle_peer_first_message(first_message);
        } catch (const Protocol::IncompatiblePeerError&) {
            is_incompatible = true;
        }

        if (is_incompatible) {
            log::Debug() << "Peer::handle IncompatiblePeerError";
            co_await (message_stream.send(DisconnectMessage{DisconnectReason::UselessPeer}.to_message()) ||
                      common::Timeout::after(kPeerDisconnectTimeout));
            co_return;
        }

        handshake_promise_.set_value(true);

        bool is_disconnecting = false;
        bool is_cancelled = false;
        bool is_ping_timed_out = false;

        try {
            co_await (
                send_messages(message_stream) &&
                receive_messages(message_stream) &&
                ping_periodically(message_stream));
        } catch (const DisconnectedError&) {
            is_disconnecting = true;
        } catch (const PingTimeoutError&) {
            is_ping_timed_out = true;
        } catch (const boost::system::system_error& ex) {
            if (ex.code() == boost::system::errc::operation_canceled) {
                is_cancelled = true;
            } else {
                throw;
            }
        }

        if (is_disconnecting) {
            log::Debug() << "Peer::handle disconnecting";
            auto reason = disconnect_reason_.get().value_or(DisconnectReason::DisconnectRequested);
            co_await (message_stream.send(DisconnectMessage{reason}.to_message()) ||
                      common::Timeout::after(kPeerDisconnectTimeout));
        }

        if (is_cancelled) {
            log::Debug() << "Peer::handle cancelled - quitting gracefully";
            co_await boost::asio::this_coro::reset_cancellation_state();
            co_await (message_stream.send(DisconnectMessage{DisconnectReason::ClientQuitting}.to_message()) ||
                      common::Timeout::after(kPeerDisconnectTimeout));
            throw boost::system::system_error(make_error_code(boost::system::errc::operation_canceled));
        }

        if (is_ping_timed_out) {
            log::Debug() << "Peer::handle ping timed out";
            co_await (message_stream.send(DisconnectMessage{DisconnectReason::PingTimeout}.to_message()) ||
                      common::Timeout::after(kPeerDisconnectTimeout));
        }

    } catch (const auth::Handshake::DisconnectError&) {
        log::Debug() << "Peer::handle DisconnectError";
    } catch (const common::Timeout::ExpiredError&) {
        log::Debug() << "Peer::handle timeout expired";
    } catch (const boost::system::system_error& ex) {
        if (is_fatal_network_error(ex)) {
            log::Debug() << "Peer::handle network error: " << ex.what();
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

awaitable<void> Peer::drop(const std::shared_ptr<Peer>& peer, DisconnectReason reason) {
    return co_spawn(peer->strand_, Peer::drop_in_strand(peer, reason), use_awaitable);
}

awaitable<void> Peer::drop_in_strand(std::shared_ptr<Peer> self, DisconnectReason reason) {
    co_await self->drop(reason);
}

awaitable<void> Peer::drop(DisconnectReason reason) {
    using namespace common::awaitable_wait_for_one;

    log::Debug() << "Peer::drop reason " << static_cast<int>(reason);
    auto _ = gsl::finally([this] { this->close(); });

    try {
        auto message_stream = co_await handshake();
        co_await (message_stream.send(DisconnectMessage{reason}.to_message()) ||
                  common::Timeout::after(kPeerDisconnectTimeout));
    } catch (const auth::Handshake::DisconnectError&) {
        log::Debug() << "Peer::drop DisconnectError";
    } catch (const common::Timeout::ExpiredError&) {
        log::Debug() << "Peer::drop timeout expired";
    } catch (const boost::system::system_error& ex) {
        if (is_fatal_network_error(ex)) {
            log::Debug() << "Peer::drop network error: " << ex.what();
            co_return;
        } else if (ex.code() == boost::system::errc::operation_canceled) {
            log::Debug() << "Peer::drop cancelled";
            co_return;
        }
        log::Error() << "Peer::drop system_error: " << ex.what();
        throw;
    } catch (const std::exception& ex) {
        log::Error() << "Peer::drop exception: " << ex.what();
        throw;
    }
}

void Peer::disconnect(DisconnectReason reason) {
    log::Debug() << "Peer::disconnect reason " << static_cast<int>(reason);
    disconnect_reason_.set({reason});
    this->close();
}

awaitable<framing::MessageStream> Peer::handshake() {
    auth::Handshake handshake{
        node_key_,
        client_id_,
        node_listen_port_,
        protocol_->capability(),
        peer_public_key_.get(),
    };
    auto result = co_await handshake.execute(stream_);
    peer_public_key_.set(std::move(result.peer_public_key));
    hello_message_.set(std::move(result.hello_reply_message));
    co_return std::move(result.message_stream);
}

awaitable<bool> Peer::wait_for_handshake(std::shared_ptr<Peer> self) {
    co_return (co_await self->handshake_promise_.wait());
}

void Peer::close() {
    try {
        send_message_channel_.close();
        receive_message_channel_.close();
        pong_channel_.close();
    } catch (const std::exception& ex) {
        log::Warning() << "Peer::close exception: " << ex.what();
    }
}

void Peer::post_message(const std::shared_ptr<Peer>& peer, const common::Message& message) {
    peer->send_message_tasks_.spawn(peer->strand_, Peer::send_message(peer, message));
}

awaitable<void> Peer::send_message_tasks_wait(std::shared_ptr<Peer> self) {
    co_await self->send_message_tasks_.wait();
}

awaitable<void> Peer::send_message(std::shared_ptr<Peer> peer, common::Message message) {
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

awaitable<void> Peer::send_message(common::Message message) {
    try {
        co_await send_message_channel_.send(std::move(message));
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::asio::experimental::error::channel_closed)
            throw DisconnectedError();
        throw;
    }
}

awaitable<void> Peer::send_messages(framing::MessageStream& message_stream) {
    // loop until message_stream exception
    while (true) {
        common::Message message;
        try {
            message = co_await send_message_channel_.receive();
        } catch (const boost::system::system_error& ex) {
            if (ex.code() == boost::asio::experimental::error::channel_closed)
                throw DisconnectedError();
            throw;
        }
        co_await message_stream.send(std::move(message));
    }
}

awaitable<common::Message> Peer::receive_message() {
    try {
        co_return (co_await receive_message_channel_.receive());
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::asio::experimental::error::channel_closed)
            throw DisconnectedError();
        throw;
    }
}

awaitable<void> Peer::receive_messages(framing::MessageStream& message_stream) {
    // loop until message_stream exception
    while (true) {
        auto message = co_await message_stream.receive();

        if (message.id == DisconnectMessage::kId) {
            throw auth::Handshake::DisconnectError();
        } else if (message.id == PingMessage::kId) {
            co_await message_stream.send(PongMessage{}.to_message());
            continue;
        } else if (message.id == PongMessage::kId) {
            try {
                co_await pong_channel_.send(std::move(message));
            } catch (const boost::system::system_error& ex) {
                if (ex.code() == boost::asio::experimental::error::channel_closed)
                    throw DisconnectedError();
                throw;
            }
            continue;
        }

        try {
            co_await receive_message_channel_.send(std::move(message));
        } catch (const boost::system::system_error& ex) {
            if (ex.code() == boost::asio::experimental::error::channel_closed)
                throw DisconnectedError();
            throw;
        }
    }
}

awaitable<void> Peer::ping_periodically(framing::MessageStream& message_stream) {
    using namespace common::awaitable_wait_for_one;

    // loop until message_stream exception
    while (true) {
        co_await common::sleep(kPeerPingInterval);

        co_await message_stream.send(PingMessage{}.to_message());

        try {
            co_await (pong_channel_.receive() || common::Timeout::after(kPeerPingInterval / 3));
        } catch (const common::Timeout::ExpiredError&) {
            throw PingTimeoutError();
        } catch (const boost::system::system_error& ex) {
            if (ex.code() == boost::asio::experimental::error::channel_closed)
                throw DisconnectedError();
            throw;
        }
    }
}

}  // namespace silkworm::sentry::rlpx
