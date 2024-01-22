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

#include <stack>
#include <string>
#include <string_view>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/rpc/types/writer.hpp>

namespace silkworm::rpc::json {
static const nlohmann::json JSON_NULL = nlohmann::json::value_t::null;
static const nlohmann::json EMPTY_OBJECT = nlohmann::json::value_t::object;
static const nlohmann::json EMPTY_ARRAY = nlohmann::json::value_t::array;

class Stream {
  public:
    explicit Stream(boost::asio::any_io_executor& executor, StreamWriter& writer, std::size_t threshold = kDefaultThreshold);
    Stream(const Stream& stream) = delete;
    Stream& operator=(const Stream&) = delete;

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
    void write_field(std::string_view name, std::float_t value);
    void write_field(std::string_view name, std::double_t value);

  private:
    static const std::size_t kDefaultThreshold = 0x800;

    void write_string(std::string_view str);
    void ensure_separator();

    void write(std::string_view str);
    void do_write(std::shared_ptr<std::string> ptr);

    Task<void> run();

    boost::asio::any_io_executor& io_executor_;

    StreamWriter& writer_;
    std::stack<std::uint8_t> stack_;

    const std::size_t threshold_;
    std::string buffer_;

    bool closed_{false};
    Task<void> runner_task_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::shared_ptr<std::string>)> channel_;
};

}  // namespace silkworm::rpc::json
