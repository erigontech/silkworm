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

#pragma once

#include <memory>
#include <stack>
#include <string>
#include <string_view>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/experimental/concurrent_channel.hpp>
#ifndef _WIN32  // Workaround for Windows build error due to bug https://github.com/chriskohlhoff/asio/issues/1281
#include <boost/asio/experimental/promise.hpp>
#endif  // _WIN32
#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/rpc/types/writer.hpp>

namespace silkworm::rpc::json {

struct DataChunk {
    std::shared_ptr<std::string> chunk;
    bool last{false};
};

//! Stream can be used to send big JSON data split into multiple fragments.
class Stream {
  public:
    inline static constexpr std::size_t kDefaultCapacity{5 * 1024 * 1024};

    Stream(boost::asio::any_io_executor& executor, StreamWriter& writer, std::size_t buffer_capacity = kDefaultCapacity);
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

    const std::size_t buffer_capacity_;
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
