/*
   Copyright 2020 The Silkrpc Authors

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

#include <silkworm/silkrpc/config.hpp>

#include <memory>
#include <optional>
#include <string>

#include <boost/asio/awaitable.hpp>

#include <silkworm/core/common/util.hpp>

#include <silkworm/silkrpc/common/util.hpp>

namespace silkrpc::core::rawdb {

using Walker = std::function<bool(silkworm::Bytes&, silkworm::Bytes&)>;

class DatabaseReader {
public:
    virtual boost::asio::awaitable<KeyValue> get(const std::string& table, const silkworm::ByteView& key) const = 0;

    virtual boost::asio::awaitable<silkworm::Bytes> get_one(const std::string& table, const silkworm::ByteView& key) const = 0;

    virtual boost::asio::awaitable<std::optional<silkworm::Bytes>> get_both_range(const std::string& table, const silkworm::ByteView& key, const silkworm::ByteView& subkey) const = 0;

    virtual boost::asio::awaitable<void> walk(const std::string& table, const silkworm::ByteView& start_key, uint32_t fixed_bits, Walker w) const = 0;

    virtual boost::asio::awaitable<void> for_prefix(const std::string& table, const silkworm::ByteView& prefix, Walker w) const = 0;
};

} // namespace silkrpc::core::rawdb

