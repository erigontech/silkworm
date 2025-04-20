// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>

#include <silkworm/rpc/commands/rpc_api_table.hpp>
#include <silkworm/rpc/transport/request_handler.hpp>
#include <silkworm/rpc/transport/stream_writer.hpp>

namespace silkworm::rpc::ws {

using TcpStream = boost::beast::websocket::stream<boost::beast::tcp_stream>;

inline constexpr size_t kDefaultCapacity = 5 * 1024 * 1024;

//! Represents a single connection from a client via websocket.
class Connection : public StreamWriter {
  public:
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    //! Construct a connection running within the given execution context.
    Connection(TcpStream&& stream,
               RequestHandlerFactory& handler_factory,
               bool compression = false);

    ~Connection() override;

    Task<void> accept(const boost::beast::http::request<boost::beast::http::string_body>& req);

    Task<void> read_loop();

    // Methods of StreamWriter interface
    Task<void> open_stream(uint64_t /* request_id */) override { co_return; }
    Task<void> close_stream(uint64_t /* request_id */) override { co_return; }
    size_t get_capacity() const noexcept override { return kDefaultCapacity; }
    Task<size_t> write(uint64_t request_id, std::string_view content, bool last) override;

  private:
    Task<void> do_read();

    //! Perform an asynchronous write operation.
    Task<size_t> do_write(const std::string& content);

    //! The WebSocket TCP stream
    TcpStream stream_;

    //! The handler used to process the incoming request.
    RequestHandlerPtr handler_;

    //! enable compress flag
    bool compression_{false};
};

}  // namespace silkworm::rpc::ws
