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

#include "stream.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <iostream>
#include <string>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/compose.hpp>
#include <boost/asio/use_future.hpp>

namespace silkworm::rpc::json {

static std::uint8_t kObjectOpen = 1;
static std::uint8_t kArrayOpen = 2;
static std::uint8_t kFieldWritten = 3;
static std::uint8_t kEntryWritten = 4;

static std::string kOpenBrace{"{"};       // NOLINT(runtime/string)
static std::string kCloseBrace{"}"};      // NOLINT(runtime/string)
static std::string kOpenBracket{"["};     // NOLINT(runtime/string)
static std::string kCloseBracket{"]"};    // NOLINT(runtime/string)
static std::string kFieldSeparator{","};  // NOLINT(runtime/string)
static std::string kColon{":"};           // NOLINT(runtime/string)
static std::string kDoubleQuotes{"\""};   // NOLINT(runtime/string)

Task<void> Stream::close() {
    // std::cout << "COMPLETING.... \n";

    auto current_executor = co_await boost::asio::this_coro::executor;

    std::string to_write(buffer_);
    buffer_.clear();

    co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(void)>(
        [&](auto&& self) {
            boost::asio::post(executor_, [&, self = std::move(self), value = std::move(to_write)]() mutable {
                if (value.size() > 0) {
                    // std::cout << "WRITE " << value << " \n";
                    writer_.write(value);
                }
                // std::cout << "CLOSE \n";
                writer_.close();
                boost::asio::post(current_executor, [self = std::move(self)]() mutable {
                    // std::cout << "COMPLETING...\n";
                    self.complete();
                });
            });
        },
        boost::asio::use_awaitable);

    // std::cout << "COMPLETED \n";

    co_return;
}

// Task<void> Stream::close() {
//     auto current_executor = co_await boost::asio::this_coro::executor;
//     co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(void)>(
//         [&](auto&& self) {
//             boost::asio::post(executor_, [&, self = std::move(self)]() mutable {
//             writer_.close();
//             boost::asio::post(current_executor, [self = std::move(self)]() mutable {
//                 self.complete();
//             });
//         });
//     }, boost::asio::use_awaitable);

//     co_return;
// }

void Stream::open_object() {
    bool isEntry = !stack_.empty() && (stack_.top() == kArrayOpen || stack_.top() == kEntryWritten);
    if (isEntry) {
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
    bool isEntry = !stack_.empty() && (stack_.top() == kArrayOpen || stack_.top() == kEntryWritten);
    if (isEntry) {
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

void Stream::write_field(std::string_view name, std::float_t value) {
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
    if (buffer_.size() >= threshold_) {
        std::string to_write(buffer_);
        buffer_.clear();
        boost::asio::post(executor_, [&, value = std::move(to_write)]() mutable {
            // std::cout << "WRITE: " << value << " \n";
            writer_.write(value);
        });
    }
}

// void Stream::write(std::string_view str) {
//     std::string to_write(str);
//     boost::asio::post(executor_, [&, value = std::move(to_write)]() mutable {
//         writer_.write(value);
//     });
// }

void Stream::ensure_separator() {
    if (!stack_.empty()) {
        if (stack_.top() != kFieldWritten) {
            stack_.push(kFieldWritten);
        } else {
            write(kFieldSeparator);
        }
    }
}

}  // namespace silkworm::rpc::json
