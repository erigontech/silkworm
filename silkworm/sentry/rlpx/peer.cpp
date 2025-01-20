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

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/sleep.hpp>
#include <silkworm/infra/concurrency/spawn.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>

#include "auth/auth_message_error.hpp"
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
      local_endpoint_(stream_.socket().local_endpoint()),
      remote_endpoint_(stream_.socket().remote_endpoint()),
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
    SILK_TRACE_M("sentry") << "silkworm::sentry::rlpx::Peer::~Peer";
}

Task<void> Peer::run(std::shared_ptr<Peer> peer) {
    using namespace concurrency::awaitable_wait_for_one;

    auto run = peer->handle() || peer->send_message_tasks_.wait();
    co_await concurrency::spawn_task(peer->strand_, std::move(run));
}

static bool is_fatal_network_error(const boost::system::system_error& ex) {
    auto code = ex.code();
    return (code == boost::asio::error::eof) ||
           (code == boost::asio::error::connection_reset) ||
           (code == boost::asio::error::broken_pipe);
}

static constexpr std::chrono::milliseconds kPeerDisconnectTimeout = 2s;
static constexpr std::chrono::milliseconds kPeerPingInterval = 15s;

class PingTimeoutError : public std::runtime_error {
  public:
    PingTimeoutError() : std::runtime_error("rlpx::Peer ping timed out") {}
};

Task<void> Peer::handle() {
    using namespace concurrency::awaitable_wait_for_all;
    using namespace concurrency::awaitable_wait_for_one;

    SILK_TRACE_M("sentry") << "Peer::handle";

    [[maybe_unused]] auto _ = gsl::finally([this] {
        try {
            this->handshake_promise_.set_value(false);
        } catch (const concurrency::AwaitablePromise<bool>::AlreadySatisfiedError&) {
            SILK_TRACE_M("sentry") << "Peer::handle AlreadySatisfiedError";
        }
        this->close();
    });

    try {
        auto message_stream = co_await handshake();

        co_await message_stream.send(protocol_->first_message());
        auto first_message = co_await message_stream.receive();
        SILK_TRACE_M("sentry") << "Peer::handle first_message: " << int{first_message.id};

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
            SILK_DEBUG_M("sentry") << "Peer::handle IncompatiblePeerError";
            disconnect_reason_.set({DisconnectReason::kUselessPeer});
            co_await (message_stream.send(DisconnectMessage{DisconnectReason::kUselessPeer}.to_message()) ||
                      concurrency::timeout(kPeerDisconnectTimeout));
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
            SILK_DEBUG_M("sentry") << "Peer::handle disconnecting";
            auto reason = disconnect_reason_.get().value_or(DisconnectReason::kDisconnectRequested);
            disconnect_reason_.set({reason});
            co_await (message_stream.send(DisconnectMessage{reason}.to_message()) ||
                      concurrency::timeout(kPeerDisconnectTimeout));
        }

        if (is_cancelled) {
            SILK_DEBUG_M("sentry") << "Peer::handle cancelled - quitting gracefully";
            co_await boost::asio::this_coro::reset_cancellation_state();
            disconnect_reason_.set({DisconnectReason::kClientQuitting});
            co_await (message_stream.send(DisconnectMessage{DisconnectReason::kClientQuitting}.to_message()) ||
                      concurrency::timeout(kPeerDisconnectTimeout));
            throw boost::system::system_error(make_error_code(boost::system::errc::operation_canceled));
        }

        if (is_ping_timed_out) {
            SILK_DEBUG_M("sentry") << "Peer::handle ping timed out";
            disconnect_reason_.set({DisconnectReason::kPingTimeout});
            co_await (message_stream.send(DisconnectMessage{DisconnectReason::kPingTimeout}.to_message()) ||
                      concurrency::timeout(kPeerDisconnectTimeout));
        }

    } catch (const auth::Handshake::DisconnectError& ex) {
        SILK_DEBUG_M("sentry") << "Peer::handle DisconnectError reason: " << static_cast<int>(ex.reason());
        disconnect_reason_.set({ex.reason()});
    } catch (const auth::AuthMessageErrorDecryptFailure& ex) {
        SILK_TRACE_M("sentry")
            << "Peer::handle AuthMessageErrorDecryptFailure"
            << " remote_endpoint: " << remote_endpoint() << ";"
            << " local_endpoint: " << local_endpoint() << ";"
            << " cause_code: " << static_cast<int>(ex.cause_code()) << ";"
            << " auth_message_type: " << static_cast<int>(ex.message_type()) << ";"
            << " auth_message: " << to_hex(ex.message_data()) << ";"
            << " description: " << ex.what() << ";";
        disconnect_reason_.set({DisconnectReason::kProtocolError});
    } catch (const framing::MessageStream::DecompressionError& ex) {
        SILK_DEBUG_M("sentry") << "Peer::handle DecompressionError: " << ex.what();
        disconnect_reason_.set({DisconnectReason::kProtocolError});
    } catch (const auth::Handshake::CapabilityMismatchError& ex) {
        SILK_DEBUG_M("sentry") << "Peer::handle CapabilityMismatchError: " << ex.what();
        disconnect_reason_.set({DisconnectReason::kUselessPeer});
    } catch (const concurrency::TimeoutExpiredError&) {
        SILK_DEBUG_M("sentry") << "Peer::handle timeout expired";
    } catch (const boost::system::system_error& ex) {
        if (is_fatal_network_error(ex)) {
            SILK_DEBUG_M("sentry") << "Peer::handle network error: " << ex.what();
            auto reason = disconnect_reason_.get().value_or(DisconnectReason::kNetworkError);
            disconnect_reason_.set({reason});
            co_return;
        } else if (ex.code() == boost::system::errc::operation_canceled) {
            SILK_WARN_M("sentry") << "Peer::handle cancelled";
            co_return;
        }
        SILK_ERROR_M("sentry") << "Peer::handle system_error: " << ex.what();
        throw;
    } catch (const std::nested_exception& ne) {
        try {
            ne.rethrow_nested();
        } catch (const DisconnectedError&) {
            SILK_DEBUG_M("sentry") << "Peer::handle nested disconnection error";
            auto reason = disconnect_reason_.get().value_or(DisconnectReason::kDisconnectRequested);
            disconnect_reason_.set({reason});
            co_return;
        } catch (const boost::system::system_error& ex) {
            if (is_fatal_network_error(ex)) {
                SILK_DEBUG_M("sentry") << "Peer::handle nested network error: " << ex.what();
                auto reason = disconnect_reason_.get().value_or(DisconnectReason::kNetworkError);
                disconnect_reason_.set({reason});
                co_return;
            } else if (ex.code() == boost::system::errc::operation_canceled) {
                SILK_DEBUG_M("sentry") << "Peer::handle nested cancellation";
                co_return;
            }
            SILK_ERROR_M("sentry") << "Peer::handle nested system_error: " << ex.what();
            throw;
        }
    } catch (const std::exception& ex) {
        SILK_ERROR_M("sentry") << "Peer::handle exception: " << ex.what();
        throw;
    }
}

Task<void> Peer::drop(const std::shared_ptr<Peer>& peer, DisconnectReason reason) {
    return concurrency::spawn_task(peer->strand_, Peer::drop_in_strand(peer, reason));
}

Task<void> Peer::drop_in_strand(std::shared_ptr<Peer> peer, DisconnectReason reason) {
    co_await peer->drop(reason);
}

Task<void> Peer::drop(DisconnectReason reason) {
    using namespace concurrency::awaitable_wait_for_one;

    SILK_DEBUG_M("sentry") << "Peer::drop reason " << static_cast<int>(reason);
    [[maybe_unused]] auto _ = gsl::finally([this] { this->close(); });

    try {
        auto message_stream = co_await handshake();
        disconnect_reason_.set({reason});
        co_await (message_stream.send(DisconnectMessage{reason}.to_message()) ||
                  concurrency::timeout(kPeerDisconnectTimeout));
    } catch (const auth::Handshake::DisconnectError& ex) {
        SILK_DEBUG_M("sentry") << "Peer::drop DisconnectError reason: " << static_cast<int>(ex.reason());
        disconnect_reason_.set({ex.reason()});
    } catch (const auth::AuthMessageErrorDecryptFailure& ex) {
        SILK_TRACE_M("sentry")
            << "Peer::drop AuthMessageErrorDecryptFailure"
            << " remote_endpoint: " << remote_endpoint() << ";"
            << " local_endpoint: " << local_endpoint() << ";"
            << " cause_code: " << static_cast<int>(ex.cause_code()) << ";"
            << " auth_message_type: " << static_cast<int>(ex.message_type()) << ";"
            << " auth_message: " << to_hex(ex.message_data()) << ";"
            << " description: " << ex.what() << ";";
        disconnect_reason_.set({DisconnectReason::kProtocolError});
    } catch (const framing::MessageStream::DecompressionError& ex) {
        SILK_DEBUG_M("sentry") << "Peer::drop DecompressionError: " << ex.what();
        disconnect_reason_.set({DisconnectReason::kProtocolError});
    } catch (const auth::Handshake::CapabilityMismatchError& ex) {
        SILK_DEBUG_M("sentry") << "Peer::drop CapabilityMismatchError: " << ex.what();
        disconnect_reason_.set({DisconnectReason::kUselessPeer});
    } catch (const concurrency::TimeoutExpiredError&) {
        SILK_DEBUG_M("sentry") << "Peer::drop timeout expired";
    } catch (const boost::system::system_error& ex) {
        if (is_fatal_network_error(ex)) {
            SILK_DEBUG_M("sentry") << "Peer::drop network error: " << ex.what();
            co_return;
        } else if (ex.code() == boost::system::errc::operation_canceled) {
            SILK_WARN_M("sentry") << "Peer::drop cancelled";
            co_return;
        }
        SILK_ERROR_M("sentry") << "Peer::drop system_error: " << ex.what();
        throw;
    } catch (const std::exception& ex) {
        SILK_ERROR_M("sentry") << "Peer::drop exception: " << ex.what();
        throw;
    }
}

void Peer::disconnect(DisconnectReason reason) {
    SILK_DEBUG_M("sentry") << "Peer::disconnect reason " << static_cast<int>(reason);
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
        SILK_WARN_M("sentry") << "Peer::close exception: " << ex.what();
    }
}

void Peer::post_message(const std::shared_ptr<Peer>& peer, const Message& message) {
    try {
        peer->send_message_tasks_.spawn(peer->strand_, Peer::send_message(peer, message));
    } catch (const concurrency::TaskGroup::SpawnAfterCloseError&) {
        SILK_WARN_M("sentry") << "Peer::post_message cannot spawn send_message after close";
    }
}

Task<void> Peer::send_message(std::shared_ptr<Peer> peer, Message message) {
    try {
        co_await peer->send_message(std::move(message));
    } catch (const DisconnectedError& ex) {
        SILK_DEBUG_M("sentry") << "Peer::send_message: " << ex.what();
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled) {
            SILK_WARN_M("sentry") << "Peer::send_message cancelled";
            co_return;
        }
        SILK_ERROR_M("sentry") << "Peer::send_message system_error: " << ex.what();
        throw;
    } catch (const std::exception& ex) {
        SILK_ERROR_M("sentry") << "Peer::send_message exception: " << ex.what();
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
        }
        if (message.id == PingMessage::kId) {
            co_await message_stream.send(PongMessage{}.to_message());
            continue;
        }
        if (message.id == PongMessage::kId) {
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
