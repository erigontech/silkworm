// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <optional>
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>

#include <silkworm/infra/concurrency/awaitable_future.hpp>
#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/infra/concurrency/task_group.hpp>
#include <silkworm/sentry/common/atomic_value.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/enode_url.hpp>
#include <silkworm/sentry/common/message.hpp>
#include <silkworm/sentry/common/socket_stream.hpp>

#include "auth/hello_message.hpp"
#include "common/disconnect_reason.hpp"
#include "framing/message_stream.hpp"
#include "protocol.hpp"

namespace silkworm::sentry::rlpx {

class Peer {
  public:
    Peer(
        const boost::asio::any_io_executor& executor,
        SocketStream stream,
        EccKeyPair node_key,
        std::string client_id,
        uint16_t node_listen_port,
        std::unique_ptr<Protocol> protocol,
        std::optional<EnodeUrl> url,
        std::optional<EccPublicKey> peer_public_key,
        bool is_inbound,
        bool is_static);

    ~Peer();

    static Task<void> run(std::shared_ptr<Peer> peer);
    static Task<void> drop(const std::shared_ptr<Peer>& peer, DisconnectReason reason);
    void disconnect(DisconnectReason reason);
    static Task<bool> wait_for_handshake(std::shared_ptr<Peer> self);

    static void post_message(const std::shared_ptr<Peer>& peer, const Message& message);
    Task<Message> receive_message();

    class DisconnectedError : public std::runtime_error {
      public:
        DisconnectedError() : std::runtime_error("rlpx::Peer is disconnected") {}
    };

    std::optional<EnodeUrl> url() {
        return url_.get();
    }

    std::optional<EccPublicKey> peer_public_key() {
        return peer_public_key_.get();
    }

    boost::asio::ip::tcp::endpoint local_endpoint() const {
        return local_endpoint_;
    }

    boost::asio::ip::tcp::endpoint remote_endpoint() const {
        return remote_endpoint_;
    }

    bool is_inbound() const { return is_inbound_; };
    bool is_static() const { return is_static_; };

    std::optional<auth::HelloMessage> hello_message() {
        return hello_message_.get();
    }

    std::optional<DisconnectReason> disconnect_reason() {
        return disconnect_reason_.get();
    }

  private:
    Task<void> handle();
    static Task<void> drop_in_strand(std::shared_ptr<Peer> peer, DisconnectReason reason);
    Task<void> drop(DisconnectReason reason);
    Task<framing::MessageStream> handshake();
    void close();

    static Task<void> send_message(std::shared_ptr<Peer> peer, Message message);
    Task<void> send_message(Message message);
    Task<void> send_messages(framing::MessageStream& message_stream);
    Task<void> receive_messages(framing::MessageStream& message_stream);
    Task<void> ping_periodically(framing::MessageStream& message_stream);

    SocketStream stream_;
    boost::asio::ip::tcp::endpoint local_endpoint_;
    boost::asio::ip::tcp::endpoint remote_endpoint_;
    EccKeyPair node_key_;
    std::string client_id_;
    uint16_t node_listen_port_;
    std::unique_ptr<Protocol> protocol_;
    AtomicValue<std::optional<EnodeUrl>> url_;
    AtomicValue<std::optional<EccPublicKey>> peer_public_key_;
    bool is_inbound_;
    bool is_static_;

    AtomicValue<std::optional<auth::HelloMessage>> hello_message_{std::nullopt};
    concurrency::AwaitablePromise<bool> handshake_promise_;
    AtomicValue<std::optional<DisconnectReason>> disconnect_reason_{std::nullopt};

    boost::asio::strand<boost::asio::any_io_executor> strand_;
    concurrency::TaskGroup send_message_tasks_;
    concurrency::Channel<Message> send_message_channel_;
    concurrency::Channel<Message> receive_message_channel_;
    concurrency::Channel<Message> pong_channel_;
};

}  // namespace silkworm::sentry::rlpx
