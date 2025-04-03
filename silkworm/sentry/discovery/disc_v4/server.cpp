// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "server.hpp"

#include <concepts>
#include <optional>
#include <stdexcept>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/udp.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/ipv6_unsupported_error.hpp>

#include "common/packet_type.hpp"
#include "message_codec.hpp"

namespace silkworm::sentry::discovery::disc_v4 {

using namespace boost::asio;

class ServerImpl {
  public:
    explicit ServerImpl(
        const any_io_executor& executor,
        uint16_t port,
        std::function<EccKeyPair()> node_key,
        MessageHandler& handler)
        : ip_(ip::address{ip::address_v4::any()}),
          port_(port),
          socket_(make_socket(executor, listen_endpoint())),
          node_key_(std::move(node_key)),
          handler_(handler) {}

    ServerImpl(const ServerImpl&) = delete;
    ServerImpl& operator=(const ServerImpl&) = delete;

    static ip::udp::socket make_socket(const any_io_executor& executor, const ip::udp::endpoint& endpoint) {
        ip::udp::socket socket{executor, endpoint.protocol()};
        socket.set_option(ip::udp::socket::reuse_address(true));

#if defined(_WIN32)
        // Windows does not have SO_REUSEPORT
        // see portability notes https://stackoverflow.com/questions/14388706/how-do-so-reuseaddr-and-so-reuseport-differ
        socket.set_option(detail::socket_option::boolean<SOL_SOCKET, SO_EXCLUSIVEADDRUSE>(true));
#else
        socket.set_option(detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT>(true));
#endif

        return socket;
    }

    void setup() {
        auto endpoint = listen_endpoint();
        socket_.bind(endpoint);
        SILK_INFO_M("sentry") << "disc_v4::Server is listening at " << endpoint;
    }

    Task<void> run() {
        Bytes packet_data_buffer(1280, 0);

        while (socket_.is_open()) {
            ip::udp::endpoint sender_endpoint;
            size_t received_count = co_await socket_.async_receive_from(buffer(packet_data_buffer), sender_endpoint, use_awaitable);
            ByteView packet_data{packet_data_buffer.data(), received_count};

            std::optional<MessageEnvelope> envelope;
            try {
                envelope = MessageCodec::decode(packet_data);
            } catch (const std::runtime_error& ex) {
                SILK_WARN_M("sentry") << "disc_v4::Server received a bad packet from " << sender_endpoint << " : " << ex.what();
                continue;
            }

            auto packet_type = static_cast<PacketType>(envelope->message.id);
            ByteView data = envelope->message.data;

            SILK_TRACE_M("sentry") << "disc_v4::Server received a packet " << static_cast<int>(packet_type);

            try {
                switch (packet_type) {
                    case PacketType::kPing:
                        co_await handler_.on_ping(
                            ping::PingMessage::rlp_decode(data),
                            std::move(envelope->public_key),
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
                        co_await handler_.on_enr_request(
                            enr::EnrRequestMessage::rlp_decode(data),
                            std::move(envelope->public_key),
                            std::move(sender_endpoint),
                            std::move(envelope->packet_hash));
                        break;
                    case PacketType::kEnrResponse:
                        co_await handler_.on_enr_response(
                            enr::EnrResponseMessage::rlp_decode(data));
                        break;
                }
            } catch (const find::FindNodeMessage::DecodeTargetPublicKeyError& ex) {
                SILK_DEBUG_M("sentry") << "disc_v4::Server received a bad message from " << sender_endpoint << " : " << ex.what();
            } catch (const enr::EnrResponseMessage::DecodeEnrRecordError& ex) {
                SILK_DEBUG_M("sentry") << "disc_v4::Server received a bad message from " << sender_endpoint << " : " << ex.what();
            } catch (const DecodingException& ex) {
                SILK_WARN_M("sentry") << "disc_v4::Server received a bad message from " << sender_endpoint << " : " << ex.what();
            }
        }
    }

    template <class TMessage>
    Task<void> send_message(const TMessage& message, ip::udp::endpoint recipient) {
        return send_message(Message{TMessage::kId, message.rlp_encode()}, std::move(recipient));
    }

    template <std::same_as<enr::EnrResponseMessage> TMessage>
    Task<void> send_message(const TMessage& message, ip::udp::endpoint recipient) {
        return send_message(Message{enr::EnrResponseMessage::kId, message.rlp_encode(node_key_())}, std::move(recipient));
    }

  private:
    ip::udp::endpoint listen_endpoint() const {
        return ip::udp::endpoint{ip_, port_};
    }

    Task<void> send_message(Message message, ip::udp::endpoint recipient) {
        auto packet_data = MessageCodec::encode(
            message,
            node_key_().private_key());
        co_await send_packet(std::move(packet_data), recipient);
    }

    Task<void> send_packet(Bytes data, ip::udp::endpoint recipient) {
        using namespace std::chrono_literals;
        using namespace concurrency::awaitable_wait_for_one;

        if (ip_.is_v4() && recipient.address().is_v6()) {
            throw IPV6UnsupportedError();
        }

        co_await (socket_.async_send_to(buffer(data), recipient, use_awaitable) || concurrency::timeout(1s));
    }

    boost::asio::ip::address ip_;
    uint16_t port_;
    ip::udp::socket socket_;
    std::function<EccKeyPair()> node_key_;
    MessageHandler& handler_;
};

Server::Server(
    const any_io_executor& executor,
    uint16_t port,
    std::function<EccKeyPair()> node_key,
    MessageHandler& handler)
    : p_impl_(std::make_unique<ServerImpl>(executor, port, std::move(node_key), handler)) {}

Server::~Server() {
    SILK_TRACE_M("sentry") << "silkworm::sentry::discovery::disc_v4::Server::~Server";
}

void Server::setup() {
    p_impl_->setup();
}

Task<void> Server::run() {
    return p_impl_->run();
}

Task<void> Server::send_ping(ping::PingMessage message, ip::udp::endpoint recipient) {
    return p_impl_->send_message(message, std::move(recipient));
}

Task<void> Server::send_pong(ping::PongMessage message, ip::udp::endpoint recipient) {
    return p_impl_->send_message(message, std::move(recipient));
}

Task<void> Server::send_find_node(find::FindNodeMessage message, ip::udp::endpoint recipient) {
    return p_impl_->send_message(message, std::move(recipient));
}

Task<void> Server::send_neighbors(find::NeighborsMessage message, ip::udp::endpoint recipient) {
    return p_impl_->send_message(message, std::move(recipient));
}

Task<void> Server::send_enr_request(enr::EnrRequestMessage message, ip::udp::endpoint recipient) {
    return p_impl_->send_message(message, std::move(recipient));
}

Task<void> Server::send_enr_response(enr::EnrResponseMessage message, ip::udp::endpoint recipient) {
    return p_impl_->send_message(message, std::move(recipient));
}

}  // namespace silkworm::sentry::discovery::disc_v4
