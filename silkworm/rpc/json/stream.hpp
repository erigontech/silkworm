// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <stack>
#include <string>
#include <string_view>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/experimental/concurrent_channel.hpp>

#include <silkworm/core/types/evmc_bytes32.hpp>
#ifndef _WIN32  // Workaround for Windows build error due to bug https://github.com/chriskohlhoff/asio/issues/1281
#include <boost/asio/experimental/promise.hpp>
#endif  // _WIN32
#include <nlohmann/json.hpp>

#include <silkworm/rpc/transport/stream_writer.hpp>

namespace silkworm::rpc::json {

struct DataChunk {
    std::shared_ptr<std::string> chunk;
    bool last{false};
};

//! Stream can be used to send big JSON data split into multiple fragments.
class Stream {
  public:
    Stream(boost::asio::any_io_executor& executor, StreamWriter& writer, size_t buffer_capacity = 0);
    Stream(const Stream& stream) = delete;
    Stream& operator=(const Stream&) = delete;

    Task<void> open();

    //! Flush any remaining data and close properly as per the underlying transport
    Task<void> close();

    void open_object();
    void close_object();

    void open_array();
    void close_array();

    void write_json(const nlohmann::json& json);
    void write_json_field(std::string_view name, const nlohmann::json& value);

    void write_field(std::string_view name);
    void write_entry(std::string_view value);
    void write_field(std::string_view name, std::string_view value);
    void write_field(std::string_view name, bool value);
    void write_field(std::string_view name, const char* value);
    void write_field(std::string_view name, std::int32_t value);
    void write_field(std::string_view name, std::uint32_t value);
    void write_field(std::string_view name, std::int64_t value);
    void write_field(std::string_view name, std::uint64_t value);
    void write_field(std::string_view name, std::double_t value);
    void write_field(std::string_view name, evmc::bytes32 value);

  private:
    using ChunkPtr = std::shared_ptr<std::string>;

    void write_string(std::string_view str);
    void ensure_separator();

    void write(std::string_view str);
    void do_write(ChunkPtr chunk, bool last);
    Task<void> do_async_write(ChunkPtr chunk, bool last);

    //! Run loop writing channeled chunks in order
    Task<void> run();

    StreamWriter& writer_;
    std::stack<std::uint8_t> stack_;

    const size_t buffer_capacity_;
    std::string buffer_;

    using ChunkChannel = boost::asio::experimental::concurrent_channel<void(boost::system::error_code, DataChunk)>;
    ChunkChannel channel_;  // Chunks enqueued waiting to be written asynchronously

// Workaround for Windows build error due to bug https://github.com/chriskohlhoff/asio/issues/1281
#ifndef _WIN32
    using RunPromise = boost::asio::experimental::promise<void(std::exception_ptr)>;
    RunPromise run_completion_promise_;  // Rendez-vous for run loop completion
#else
    using SyncChannel = boost::asio::experimental::concurrent_channel<void(boost::system::error_code, int)>;
    SyncChannel run_completion_channel_;  // Rendez-vous for run loop completion
#endif  // _WIN32
};

}  // namespace silkworm::rpc::json
