// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "stream.hpp"

#include <array>
#include <charconv>
#include <string>
#include <thread>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#ifndef _WIN32  // Workaround for Windows build error due to bug https://github.com/chriskohlhoff/asio/issues/1281
#include <boost/asio/experimental/use_promise.hpp>
#endif  // _WIN32

#include <silkworm/infra/common/log.hpp>

namespace silkworm::rpc::json {

using namespace std::chrono_literals;

static constexpr uint8_t kObjectOpen{1};
static constexpr uint8_t kArrayOpen{2};
static constexpr uint8_t kFieldWritten{3};
static constexpr uint8_t kEntryWritten{4};

static constexpr std::string_view kOpenBrace{"{"};
static constexpr std::string_view kCloseBrace{"}"};
static constexpr std::string_view kOpenBracket{"["};
static constexpr std::string_view kCloseBracket{"]"};
static constexpr std::string_view kFieldSeparator{","};
static constexpr std::string_view kColon{":"};
static constexpr std::string_view kDoubleQuotes{"\""};

//! The maximum number of items enqueued in the chunk channel
static constexpr size_t kChannelCapacity{100};

Stream::Stream(boost::asio::any_io_executor& executor, StreamWriter& writer, uint64_t request_id, size_t buffer_capacity)
    : writer_(writer),
      request_id_{request_id},
      buffer_capacity_{buffer_capacity ? buffer_capacity : writer_.get_capacity()},
      channel_{executor, kChannelCapacity},
// Workaround for Windows build error due to bug https://github.com/chriskohlhoff/asio/issues/1281
#ifndef _WIN32
      run_completion_promise_{co_spawn(
          executor, [](auto self) -> Task<void> {
              co_await self->run();
          }(this),
          boost::asio::experimental::use_promise)} {
#else
      run_completion_channel_{executor, 1} {
    co_spawn(
        executor, [](auto self) -> Task<void> {
            co_await self->run();
        }(this),
        boost::asio::detached);
#endif  // _WIN32
    // Try to prevent reallocation when buffer overflows
    buffer_.reserve(buffer_capacity_ + buffer_capacity_ / 4);
}

Task<void> Stream::open() {
    co_await writer_.open_stream(request_id_);
}

Task<void> Stream::close() {
    if (!buffer_.empty()) {
        co_await do_async_write(std::make_shared<std::string>(std::move(buffer_)), true);
    } else {
        co_await do_async_write(std::make_shared<std::string>(""), true);
    }
    co_await do_async_write(nullptr, true);

// Workaround for Windows build error due to bug https://github.com/chriskohlhoff/asio/issues/1281
#ifndef _WIN32
    co_await run_completion_promise_(boost::asio::use_awaitable);
#else
    co_await run_completion_channel_.async_receive(boost::asio::use_awaitable);
#endif  // _WIN32

    co_await writer_.close_stream(request_id_);
}

void Stream::open_object() {
    bool is_entry = !stack_.empty() && (stack_.top() == kArrayOpen || stack_.top() == kEntryWritten);
    if (is_entry) {
        if (stack_.top() != kEntryWritten) {
            stack_.push(kEntryWritten);
        } else {
            write(kFieldSeparator);
        }
    }
    write(kOpenBrace);
    stack_.push(kObjectOpen);
}

void Stream::close_object() {
    if (!stack_.empty() && stack_.top() == kFieldWritten) {
        stack_.pop();
    }
    stack_.pop();
    write(kCloseBrace);
}

void Stream::open_array() {
    write(kOpenBracket);
    stack_.push(kArrayOpen);
}

void Stream::close_array() {
    if (!stack_.empty() && (stack_.top() == kEntryWritten || stack_.top() == kFieldWritten)) {
        stack_.pop();
    }
    stack_.pop();
    write(kCloseBracket);
}

void Stream::write_json(const nlohmann::json& json) {
    const bool is_entry = !stack_.empty() && (stack_.top() == kArrayOpen || stack_.top() == kEntryWritten);
    if (is_entry) {
        if (stack_.top() != kEntryWritten) {
            stack_.push(kEntryWritten);
        } else {
            write(kFieldSeparator);
        }
    }

    const auto content = json.dump(/*indent=*/-1, /*indent_char=*/' ', /*ensure_ascii=*/false, nlohmann::json::error_handler_t::replace);
    write(content);
}

void Stream::write_field(std::string_view name) {
    ensure_separator();

    write_string(name);
    write(kColon);
}

void Stream::write_entry(std::string_view value) {
    ensure_separator();

    write_string(value);
}

void Stream::write_json_field(std::string_view name, const nlohmann::json& value) {
    ensure_separator();

    const auto content = value.dump(/*indent=*/-1, /*indent_char=*/' ', /*ensure_ascii=*/false, nlohmann::json::error_handler_t::replace);

    write_string(name);
    write(kColon);
    write(content);
}

void Stream::write_field(std::string_view name, std::string_view value) {
    ensure_separator();
    write_string(name);
    write(kColon);
    write_string(value);
}

void Stream::write_field(std::string_view name, bool value) {
    ensure_separator();
    write_string(name);
    write(kColon);
    write(value ? "true" : "false");
}

void Stream::write_field(std::string_view name, const char* value) {
    ensure_separator();
    write_string(name);
    write(kColon);
    write_string(std::string_view(value, strlen(value)));
}

void Stream::write_field(std::string_view name, evmc::bytes32 value) {
    ensure_separator();
    write_string(name);
    write(kColon);
    write_string("0x" + to_hex(value));
}

void Stream::write_field(std::string_view name, std::int32_t value) {
    ensure_separator();
    write_string(name);
    write(kColon);

    std::array<char, 10> str{};
    if (auto [ptr, ec] = std::to_chars(str.data(), str.data() + str.size(), value); ec == std::errc()) {
        write(std::string_view(str.data(), ptr));
    } else {
        write("Invalid value");
    }
}

void Stream::write_field(std::string_view name, std::uint32_t value) {
    ensure_separator();
    write_string(name);
    write(kColon);

    std::array<char, 10> str{};
    if (auto [ptr, ec] = std::to_chars(str.data(), str.data() + str.size(), value); ec == std::errc()) {
        write(std::string_view(str.data(), ptr));
    } else {
        write("Invalid value");
    }
}

void Stream::write_field(std::string_view name, std::int64_t value) {
    ensure_separator();
    write_string(name);
    write(kColon);

    std::array<char, 19> str{};
    if (auto [ptr, ec] = std::to_chars(str.data(), str.data() + str.size(), value); ec == std::errc()) {
        write(std::string_view(str.data(), ptr));
    } else {
        write("Invalid value");
    }
}

void Stream::write_field(std::string_view name, std::uint64_t value) {
    ensure_separator();
    write_string(name);
    write(kColon);

    std::array<char, 19> str{};
    if (auto [ptr, ec] = std::to_chars(str.data(), str.data() + str.size(), value); ec == std::errc()) {
        write(std::string_view(str.data(), ptr));
    } else {
        write("Invalid value");
    }
}

void Stream::write_field(std::string_view name, std::double_t value) {
    ensure_separator();
    write_string(name);
    write(kColon);

    std::array<char, 30> str{};
    if (auto [ptr, ec] = std::to_chars(str.data(), str.data() + str.size(), value); ec == std::errc()) {
        write(std::string_view(str.data(), ptr));
    } else {
        write("Invalid value");
    }
}

void Stream::write_string(std::string_view str) {
    write(kDoubleQuotes);
    write(str);
    write(kDoubleQuotes);
}

void Stream::write(std::string_view str) {
    buffer_ += str;
    if (buffer_.size() >= buffer_capacity_) {
        do_write(std::make_shared<std::string>(std::move(buffer_)), false);
    }
}

void Stream::ensure_separator() {
    if (!stack_.empty()) {
        if (stack_.top() != kFieldWritten) {
            stack_.push(kFieldWritten);
        } else {
            write(kFieldSeparator);
        }
    }
}

void Stream::do_write(ChunkPtr chunk, bool last) {
    // Stream write API will usually be called by worker threads rather than I/O contexts, but we must handle both
    const auto& channel_executor{channel_.get_executor()};
    if (channel_executor.target<boost::asio::io_context::executor_type>()->running_in_this_thread()) [[unlikely]] {
        // Delegate any back pressure to do_async_write
        boost::asio::co_spawn(channel_executor, do_async_write(chunk, false), boost::asio::detached);
    } else {
        DataChunk data_chunk{};
        data_chunk.chunk = std::move(chunk);
        data_chunk.last = last;
        // Handle back pressure simply by retrying after a while // TODO(canepat) clever wait strategy
        while (channel_.is_open()) {
            if (const bool ok{channel_.try_send(boost::system::error_code(), data_chunk)}; ok) {
                break;
            }
            SILK_TRACE << "Chunk size=" << (data_chunk.chunk ? data_chunk.chunk->size() : 0) << " not enqueued, worker back pressured";
            std::this_thread::sleep_for(10ms);
        }
    }
}

Task<void> Stream::do_async_write(ChunkPtr chunk, bool last) {
    DataChunk data_chunk{};
    data_chunk.chunk = std::move(chunk);
    data_chunk.last = last;

    // TODO(canepat) handle back pressure
    try {
        co_await channel_.async_send(boost::system::error_code(), data_chunk, boost::asio::use_awaitable);
    } catch (const boost::system::system_error& se) {
        if (se.code() != boost::asio::experimental::error::channel_cancelled) {
            SILK_ERROR << "Stream::do_async_write unexpected system_error: " << se.what();
        }
    } catch (const std::exception& exception) {
        SILK_ERROR << "Stream::do_async_write unexpected exception: " << exception.what();
    }
}

Task<void> Stream::run() {
    uint32_t total_writes{0};
    size_t total_bytes_sent{0};
    while (true) {
        try {
            const DataChunk data_chunk = co_await channel_.async_receive(boost::asio::use_awaitable);
            if (!data_chunk.chunk) {
                break;
            }
            total_bytes_sent += co_await writer_.write(request_id_, *data_chunk.chunk, data_chunk.last);
            ++total_writes;
        } catch (const boost::system::system_error& se) {
            if (se.code() != boost::asio::experimental::error::channel_cancelled) {
                SILK_ERROR << "Stream::run unexpected system_error: " << se.what();
            }
            break;
        } catch (const std::exception& exception) {
            SILK_ERROR << "Stream::run unexpected exception: " << exception.what();
            break;
        }
    }

    channel_.close();

// Workaround for Windows build error due to bug https://github.com/chriskohlhoff/asio/issues/1281
#ifdef _WIN32
    co_await run_completion_channel_.async_send(boost::system::error_code(), 0, boost::asio::use_awaitable);
#endif  // _WIN32

    SILK_TRACE << "Stream::run total_writes: " << total_writes << " total_bytes_sent: " << total_bytes_sent;
}

}  // namespace silkworm::rpc::json
