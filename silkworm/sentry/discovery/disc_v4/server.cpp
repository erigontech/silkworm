/*
   Copyright 2023 The Silkworm Authors

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

#include "server.hpp"

#include <optional>
#include <stdexcept>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/this_coro.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>

#include "common/packet_type.hpp"
#include "message_codec.hpp"

namespace silkworm::sentry::discovery::disc_v4 {

using namespace boost::asio;

class ServerImpl {
  public:
    explicit ServerImpl(uint16_t port, std::function<EccKeyPair()> node_key, MessageHandler& handler)
        : ip_(ip::address{ip::address_v4::any()}),
          port_(port),
          node_key_(std::move(node_key)),
          handler_(handler) {}

    ServerImpl(const ServerImpl&) = delete;
    ServerImpl& operator=(const ServerImpl&) = delete;

    Task<void> run() {
        auto executor = co_await this_coro::executor;

        auto endpoint = listen_endpoint();

        ip::udp::socket socket{executor, endpoint.protocol()};
        socket.set_option(ip::udp::socket::reuse_address(true));

#if defined(_WIN32)
        // Windows does not have SO_REUSEPORT
        // see portability notes https://stackoverflow.com/questions/14388706/how-do-so-reuseaddr-and-so-reuseport-differ
        socket.set_option(detail::socket_option::boolean<SOL_SOCKET, SO_EXCLUSIVEADDRUSE>(true));
#else
        socket.set_option(detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT>(true));
#endif

        socket.bind(endpoint);

        log::Info("sentry") << "disc_v4::Server is listening at " << endpoint;

        Bytes packet_data_buffer(1280, 0);

        while (socket.is_open()) {
            ip::udp::endpoint sender_endpoint;
            size_t received_count = co_await socket.async_receive_from(buffer(packet_data_buffer), sender_endpoint, use_awaitable);
            ByteView packet_data{packet_data_buffer.data(), received_count};

            std::optional<MessageEnvelope> envelope;
            try {
                envelope = MessageCodec::decode(packet_data);
            } catch (const std::runtime_error& ex) {
                log::Warning("sentry") << "disc_v4::Server received a bad packet from " << sender_endpoint << " : " << ex.what();
                continue;
            }

            auto packet_type = static_cast<PacketType>(envelope->message.id);
            ByteView data = envelope->message.data;

            log::Trace("sentry") << "disc_v4::Server received a packet " << static_cast<int>(packet_type);

            try {
                switch (packet_type) {
                    case PacketType::kPing:
                        co_await handler_.on_ping(
                            ping::PingMessage::rlp_decode(data),
                            std::move(sender_endpoint),
                            std::move(envelope->packet_hash));
                        break;
                    case PacketType::kPong:
                        co_await handler_.on_pong(
                            ping::PongMessage::rlp_decode(data),
                            std::move(envelope->public_key));
                        break;
                    case PacketType::kFindNode:
                        co_await handler_.on_find_node(
                            find::FindNodeMessage::rlp_decode(data),
                            std::move(envelope->public_key),
                            std::move(sender_endpoint));
                        break;
                    case PacketType::kNeighbors:
                        co_await handler_.on_neighbors(
                            find::NeighborsMessage::rlp_decode(data),
                            std::move(envelope->public_key));
                        break;
                    case PacketType::kEnrRequest:
                        break;
                    case PacketType::kEnrResponse:
                        break;
                }
            } catch (const DecodingException& ex) {
                log::Warning("sentry") << "disc_v4::Server received a bad message from " << sender_endpoint << " : " << ex.what();
            }
        }
    }

    template <class TMessage>
    Task<void> send_message(TMessage message, ip::udp::endpoint recipient) {
        auto packet_data = MessageCodec::encode(
            Message{TMessage::kId, message.rlp_encode()},
            node_key_().private_key());
        co_await send_packet(std::move(packet_data), recipient);
    }

  private:
    [[nodiscard]] ip::udp::endpoint listen_endpoint() const {
        return ip::udp::endpoint{ip_, port_};
    }

    Task<void> send_packet(Bytes data, ip::udp::endpoint recipient) {
        using namespace std::chrono_literals;
        using namespace concurrency::awaitable_wait_for_one;

        auto executor = co_await this_coro::executor;
        ip::udp::socket socket{executor, recipient.protocol()};
        socket.set_option(ip::udp::socket::reuse_address(true));
        socket.bind(listen_endpoint());
        co_await socket.async_connect(recipient, use_awaitable);
        co_await (socket.async_send(buffer(data), use_awaitable) || concurrency::timeout(1s));
    }

    boost::asio::ip::address ip_;
    uint16_t port_;
    std::function<EccKeyPair()> node_key_;
    MessageHandler& handler_;
};

Server::Server(uint16_t port, std::function<EccKeyPair()> node_key, MessageHandler& handler)
    : p_impl_(std::make_unique<ServerImpl>(port, std::move(node_key), handler)) {}

Server::~Server() {
    log::Trace("sentry") << "silkworm::sentry::discovery::disc_v4::Server::~Server";
}

Task<void> Server::run() {
    return p_impl_->run();
}

Task<void> Server::send_ping(ping::PingMessage message, ip::udp::endpoint recipient) {
    return p_impl_->send_message(std::move(message), std::move(recipient));
}

Task<void> Server::send_pong(ping::PongMessage message, ip::udp::endpoint recipient) {
    return p_impl_->send_message(std::move(message), std::move(recipient));
}

Task<void> Server::send_find_node(find::FindNodeMessage message, ip::udp::endpoint recipient) {
    return p_impl_->send_message(std::move(message), std::move(recipient));
}

Task<void> Server::send_neighbors(find::NeighborsMessage message, ip::udp::endpoint recipient) {
    return p_impl_->send_message(std::move(message), std::move(recipient));
}

}  // namespace silkworm::sentry::discovery::disc_v4
