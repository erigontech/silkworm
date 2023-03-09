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

#pragma once

#include <memory>
#include <optional>
#include <string>

#include <silkworm/node/concurrency/coroutine.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>

#include <silkworm/node/concurrency/channel.hpp>
#include <silkworm/sentry/common/atomic_value.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/enode_url.hpp>
#include <silkworm/sentry/common/message.hpp>
#include <silkworm/sentry/common/promise.hpp>
#include <silkworm/sentry/common/socket_stream.hpp>
#include <silkworm/sentry/common/task_group.hpp>

#include "auth/hello_message.hpp"
#include "framing/message_stream.hpp"
#include "protocol.hpp"
#include "rlpx_common/disconnect_reason.hpp"

namespace silkworm::sentry::rlpx {

class Peer {
  public:
    Peer(
        boost::asio::any_io_executor&& executor,
        common::SocketStream stream,
        common::EccKeyPair node_key,
        std::string client_id,
        uint16_t node_listen_port,
        std::unique_ptr<Protocol> protocol,
        std::optional<common::EnodeUrl> url,
        std::optional<common::EccPublicKey> peer_public_key,
        bool is_inbound,
        bool is_static);

    Peer(
        boost::asio::any_io_executor& executor,
        common::SocketStream stream,
        common::EccKeyPair node_key,
        std::string client_id,
        uint16_t node_listen_port,
        std::unique_ptr<Protocol> protocol,
        std::optional<common::EnodeUrl> url,
        std::optional<common::EccPublicKey> peer_public_key,
        bool is_inbound,
        bool is_static)
        : Peer(
              boost::asio::any_io_executor{executor},
              std::move(stream),
              std::move(node_key),
              std::move(client_id),
              node_listen_port,
              std::move(protocol),
              std::move(url),
              std::move(peer_public_key),
              is_inbound,
              is_static) {}

    Peer(
        boost::asio::io_context& io_context,
        common::SocketStream stream,
        common::EccKeyPair node_key,
        std::string client_id,
        uint16_t node_listen_port,
        std::unique_ptr<Protocol> protocol,
        std::optional<common::EnodeUrl> url,
        std::optional<common::EccPublicKey> peer_public_key,
        bool is_inbound,
        bool is_static)
        : Peer(
              boost::asio::any_io_executor{io_context.get_executor()},
              std::move(stream),
              std::move(node_key),
              std::move(client_id),
              node_listen_port,
              std::move(protocol),
              std::move(url),
              std::move(peer_public_key),
              is_inbound,
              is_static) {}

    ~Peer();

    static boost::asio::awaitable<void> start(std::shared_ptr<Peer> peer);
    static boost::asio::awaitable<void> drop(const std::shared_ptr<Peer>& peer, rlpx_common::DisconnectReason reason);
    void disconnect(rlpx_common::DisconnectReason reason);
    static boost::asio::awaitable<bool> wait_for_handshake(std::shared_ptr<Peer> self);

    static void post_message(const std::shared_ptr<Peer>& peer, const common::Message& message);
    boost::asio::awaitable<common::Message> receive_message();

    class DisconnectedError : public std::runtime_error {
      public:
        DisconnectedError() : std::runtime_error("Peer is disconnected") {}
    };

    std::optional<common::EnodeUrl> url() {
        return url_.get();
    }

    std::optional<common::EccPublicKey> peer_public_key() {
        return peer_public_key_.get();
    }

    boost::asio::ip::tcp::endpoint local_endpoint() const {
        return stream_.socket().local_endpoint();
    }

    boost::asio::ip::tcp::endpoint remote_endpoint() const {
        return stream_.socket().remote_endpoint();
    }

    bool is_inbound() const { return is_inbound_; };
    bool is_static() const { return is_static_; };

    std::optional<auth::HelloMessage> hello_message() {
        return hello_message_.get();
    }

  private:
    static boost::asio::awaitable<void> handle(std::shared_ptr<Peer> peer);
    boost::asio::awaitable<void> handle();
    static boost::asio::awaitable<void> drop_in_strand(std::shared_ptr<Peer> peer, rlpx_common::DisconnectReason reason);
    boost::asio::awaitable<void> drop(rlpx_common::DisconnectReason reason);
    boost::asio::awaitable<framing::MessageStream> handshake();
    void close();

    static boost::asio::awaitable<void> send_message_tasks_wait(std::shared_ptr<Peer> self);
    static boost::asio::awaitable<void> send_message(std::shared_ptr<Peer> peer, common::Message message);
    boost::asio::awaitable<void> send_message(common::Message message);
    boost::asio::awaitable<void> send_messages(framing::MessageStream& message_stream);
    boost::asio::awaitable<void> receive_messages(framing::MessageStream& message_stream);
    boost::asio::awaitable<void> ping_periodically(framing::MessageStream& message_stream);

    common::SocketStream stream_;
    common::EccKeyPair node_key_;
    std::string client_id_;
    uint16_t node_listen_port_;
    std::unique_ptr<Protocol> protocol_;
    common::AtomicValue<std::optional<common::EnodeUrl>> url_;
    common::AtomicValue<std::optional<common::EccPublicKey>> peer_public_key_;
    bool is_inbound_;
    bool is_static_;

    common::AtomicValue<std::optional<auth::HelloMessage>> hello_message_{std::nullopt};
    common::Promise<bool> handshake_promise_;
    common::AtomicValue<std::optional<rlpx_common::DisconnectReason>> disconnect_reason_{std::nullopt};

    boost::asio::strand<boost::asio::any_io_executor> strand_;
    common::TaskGroup send_message_tasks_;
    concurrency::Channel<common::Message> send_message_channel_;
    concurrency::Channel<common::Message> receive_message_channel_;
    concurrency::Channel<common::Message> pong_channel_;
};

}  // namespace silkworm::sentry::rlpx
