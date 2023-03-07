/*
   Copyright 2022 The Silkrpc Authors

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

#include <nlohmann/json.hpp>

#include <silkworm/silkrpc/types/writer.hpp>

namespace json {
static const nlohmann::json JSON_NULL = nlohmann::json::value_t::null;
static const nlohmann::json EMPTY_OBJECT = nlohmann::json::value_t::object;
static const nlohmann::json EMPTY_ARRAY = nlohmann::json::value_t::array;

class Stream {
public:
    explicit Stream(silkrpc::Writer& writer) : writer_(writer) {}
    Stream(const Stream& stream) = delete;
    Stream& operator=(const Stream&) = delete;

    void close() {writer_.close();}

    void open_object();
    void close_object();

    void open_array();
    void close_array();

    void write_json(const nlohmann::json& json);

    void write_field(const std::string& name);
    void write_field(const std::string& name, const nlohmann::json& value);

private:
    void write_string(const std::string& str);
    void ensure_separator();

    silkrpc::Writer& writer_;
    std::stack<std::uint8_t> stack_;
};

} // namespace json

