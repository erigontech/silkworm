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
#include <optional>
#include <string>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/silkrpc/common/util.hpp>

namespace silkworm::rpc::core::rawdb {

using boost::asio::awaitable;
using Walker = std::function<bool(silkworm::Bytes&, silkworm::Bytes&)>;

class DatabaseReader {
  public:
    virtual ~DatabaseReader() = default;

    [[nodiscard]] virtual awaitable<KeyValue> get(const std::string& table, silkworm::ByteView key) const = 0;

    [[nodiscard]] virtual awaitable<silkworm::Bytes> get_one(const std::string& table, silkworm::ByteView key) const = 0;

    [[nodiscard]] virtual awaitable<std::optional<silkworm::Bytes>> get_both_range(const std::string& table, silkworm::ByteView key, silkworm::ByteView subkey) const = 0;

    [[nodiscard]] virtual awaitable<void> walk(const std::string& table, silkworm::ByteView start_key, uint32_t fixed_bits, Walker w) const = 0;

    [[nodiscard]] virtual awaitable<void> for_prefix(const std::string& table, silkworm::ByteView prefix, Walker w) const = 0;
};

}  // namespace silkworm::rpc::core::rawdb
