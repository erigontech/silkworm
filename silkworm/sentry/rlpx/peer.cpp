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

#include <boost/asio/this_coro.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>
#include <gsl/util>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/co_spawn_sw.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>
#include <silkworm/sentry/common/sleep.hpp>

#include "auth/handshake.hpp"
#include "common/disconnect_message.hpp"
#include "ping_message.hpp"

namespace silkworm::sentry::rlpx {

using namespace std::chrono_literals;
using namespace boost::asio;

Peer::Peer(
    const any_io_executor& executor,
    SocketStream stream,
    EccKeyPair node_key,
    std::string client_id,
    uint16_t node_listen_port,
    std::unique_ptr<Protocol> protocol,
    std::optional<EnodeUrl> url,
    std::optional<EccPublicKey> peer_public_key,
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
    log::Trace("sentry") << "silkworm::sentry::rlpx::Peer::~Peer";
}

Task<void> Peer::run(std::shared_ptr<Peer> peer) {
    using namespace concurrency::awaitable_wait_for_one;

    auto run = peer->handle() || peer->send_message_tasks_.wait();
    co_await concurrency::co_spawn_sw(peer->strand_, std::move(run), use_awaitable);
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
    PingTimeoutError() : std::runtime_error("rlpx::Peer ping timed out") {}
};

Task<void> Peer::handle() {
    using namespace concurrency::awaitable_wait_for_all;
    using namespace concurrency::awaitable_wait_for_one;

    log::Trace("sentry") << "Peer::handle";

    bool is_handshake_completed = false;
    [[maybe_unused]] auto _ = gsl::finally([this, &is_handshake_completed] {
        if (!is_handshake_completed) {
            this->handshake_promise_.set_value(false);
        }
        this->close();
    });

    try {
        auto message_stream = co_await handshake();

        co_await message_stream.send(protocol_->first_message());
        auto first_message = co_await message_stream.receive();
        log::Trace("sentry") << "Peer::handle first_message: " << int(first_message.id);

        if (first_message.id == DisconnectMessage::kId) {
            auto disconnect_message = DisconnectMessage::from_message(first_message);
            throw auth::Handshake::DisconnectError(disconnect_message.reason);
        }

        bool is_incompatible = false;
        try {
            protocol_->handle_peer_first_message(first_message);
        } catch (const Protocol::IncompatiblePeerError&) {
            is_incompatible = true;
        }

        if (is_incompatible) {
            log::Debug("sentry") << "Peer::handle IncompatiblePeerError";
            disconnect_reason_.set({DisconnectReason::UselessPeer});
            co_await (message_stream.send(DisconnectMessage{DisconnectReason::UselessPeer}.to_message()) ||
                      concurrency::timeout(kPeerDisconnectTimeout));
            co_return;
        }

        handshake_promise_.set_value(true);
        is_handshake_completed = true;

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
            log::Debug("sentry") << "Peer::handle disconnecting";
            auto reason = disconnect_reason_.get().value_or(DisconnectReason::DisconnectRequested);
            disconnect_reason_.set({reason});
            co_await (message_stream.send(DisconnectMessage{reason}.to_message()) ||
                      concurrency::timeout(kPeerDisconnectTimeout));
        }

        if (is_cancelled) {
            log::Debug("sentry") << "Peer::handle cancelled - quitting gracefully";
            co_await boost::asio::this_coro::reset_cancellation_state();
            disconnect_reason_.set({DisconnectReason::ClientQuitting});
            co_await (message_stream.send(DisconnectMessage{DisconnectReason::ClientQuitting}.to_message()) ||
                      concurrency::timeout(kPeerDisconnectTimeout));
            throw boost::system::system_error(make_error_code(boost::system::errc::operation_canceled));
        }

        if (is_ping_timed_out) {
            log::Debug("sentry") << "Peer::handle ping timed out";
            disconnect_reason_.set({DisconnectReason::PingTimeout});
            co_await (message_stream.send(DisconnectMessage{DisconnectReason::PingTimeout}.to_message()) ||
                      concurrency::timeout(kPeerDisconnectTimeout));
        }

    } catch (const auth::Handshake::DisconnectError& ex) {
        log::Debug("sentry") << "Peer::handle DisconnectError reason: " << static_cast<int>(ex.reason());
        disconnect_reason_.set({ex.reason()});
    } catch (const auth::Handshake::CapabilityMismatchError& ex) {
        log::Debug("sentry") << "Peer::handle CapabilityMismatchError: " << ex.what();
        disconnect_reason_.set({DisconnectReason::UselessPeer});
    } catch (const concurrency::TimeoutExpiredError&) {
        log::Debug("sentry") << "Peer::handle timeout expired";
    } catch (const boost::system::system_error& ex) {
        if (is_fatal_network_error(ex)) {
            log::Debug("sentry") << "Peer::handle network error: " << ex.what();
            auto reason = disconnect_reason_.get().value_or(DisconnectReason::NetworkError);
            disconnect_reason_.set({reason});
            co_return;
        } else if (ex.code() == boost::system::errc::operation_canceled) {
            log::Debug("sentry") << "Peer::handle cancelled";
            co_return;
        }
        log::Error("sentry") << "Peer::handle system_error: " << ex.what();
        throw;
    } catch (const std::exception& ex) {
        log::Error("sentry") << "Peer::handle exception: " << ex.what();
        throw;
    }
}

Task<void> Peer::drop(const std::shared_ptr<Peer>& peer, DisconnectReason reason) {
    return concurrency::co_spawn_sw(peer->strand_, Peer::drop_in_strand(peer, reason), use_awaitable);
}

Task<void> Peer::drop_in_strand(std::shared_ptr<Peer> self, DisconnectReason reason) {
    co_await self->drop(reason);
}

Task<void> Peer::drop(DisconnectReason reason) {
    using namespace concurrency::awaitable_wait_for_one;

    log::Debug("sentry") << "Peer::drop reason " << static_cast<int>(reason);
    [[maybe_unused]] auto _ = gsl::finally([this] { this->close(); });

    try {
        auto message_stream = co_await handshake();
        disconnect_reason_.set({reason});
        co_await (message_stream.send(DisconnectMessage{reason}.to_message()) ||
                  concurrency::timeout(kPeerDisconnectTimeout));
    } catch (const auth::Handshake::DisconnectError& ex) {
        log::Debug("sentry") << "Peer::drop DisconnectError reason: " << static_cast<int>(ex.reason());
        disconnect_reason_.set({ex.reason()});
    } catch (const concurrency::TimeoutExpiredError&) {
        log::Debug("sentry") << "Peer::drop timeout expired";
    } catch (const boost::system::system_error& ex) {
        if (is_fatal_network_error(ex)) {
            log::Debug("sentry") << "Peer::drop network error: " << ex.what();
            co_return;
        } else if (ex.code() == boost::system::errc::operation_canceled) {
            log::Debug("sentry") << "Peer::drop cancelled";
            co_return;
        }
        log::Error("sentry") << "Peer::drop system_error: " << ex.what();
        throw;
    } catch (const std::exception& ex) {
        log::Error("sentry") << "Peer::drop exception: " << ex.what();
        throw;
    }
}

void Peer::disconnect(DisconnectReason reason) {
    log::Debug("sentry") << "Peer::disconnect reason " << static_cast<int>(reason);
    disconnect_reason_.set({reason});
    this->close();
}

Task<framing::MessageStream> Peer::handshake() {
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

Task<bool> Peer::wait_for_handshake(std::shared_ptr<Peer> self) {
    auto future = self->handshake_promise_.get_future();
    co_return (co_await future.get_async());
}

void Peer::close() {
    try {
        send_message_channel_.close();
        receive_message_channel_.close();
        pong_channel_.close();
    } catch (const std::exception& ex) {
        log::Warning("sentry") << "Peer::close exception: " << ex.what();
    }
}

void Peer::post_message(const std::shared_ptr<Peer>& peer, const Message& message) {
    peer->send_message_tasks_.spawn(peer->strand_, Peer::send_message(peer, message));
}

Task<void> Peer::send_message(std::shared_ptr<Peer> peer, Message message) {
    try {
        co_await peer->send_message(std::move(message));
    } catch (const DisconnectedError& ex) {
        log::Debug("sentry") << "Peer::send_message: " << ex.what();
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled) {
            log::Debug("sentry") << "Peer::send_message cancelled";
            co_return;
        }
        log::Error("sentry") << "Peer::send_message system_error: " << ex.what();
        throw;
    } catch (const std::exception& ex) {
        log::Error("sentry") << "Peer::send_message exception: " << ex.what();
        throw;
    }
}

Task<void> Peer::send_message(Message message) {
    try {
        co_await send_message_channel_.send(std::move(message));
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::asio::experimental::error::channel_closed)
            throw DisconnectedError();
        throw;
    }
}

Task<void> Peer::send_messages(framing::MessageStream& message_stream) {
    // loop until message_stream exception
    while (true) {
        Message message;
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

Task<Message> Peer::receive_message() {
    try {
        co_return (co_await receive_message_channel_.receive());
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::asio::experimental::error::channel_closed)
            throw DisconnectedError();
        throw;
    }
}

Task<void> Peer::receive_messages(framing::MessageStream& message_stream) {
    // loop until message_stream exception
    while (true) {
        auto message = co_await message_stream.receive();

        if (message.id == DisconnectMessage::kId) {
            auto disconnect_message = DisconnectMessage::from_message(message);
            throw auth::Handshake::DisconnectError(disconnect_message.reason);
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

Task<void> Peer::ping_periodically(framing::MessageStream& message_stream) {
    using namespace concurrency::awaitable_wait_for_one;

    // loop until message_stream exception
    while (true) {
        co_await sleep(kPeerPingInterval);

        co_await message_stream.send(PingMessage{}.to_message());

        try {
            co_await (pong_channel_.receive() || concurrency::timeout(kPeerPingInterval / 3));
        } catch (const concurrency::TimeoutExpiredError&) {
            throw PingTimeoutError();
        } catch (const boost::system::system_error& ex) {
            if (ex.code() == boost::asio::experimental::error::channel_closed)
                throw DisconnectedError();
            throw;
        }
    }
}

}  // namespace silkworm::sentry::rlpx
