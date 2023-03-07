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

#include <memory>
#include <string>

#include <silkworm/silkrpc/config.hpp>

#include <boost/asio/awaitable.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/ethdb/cursor.hpp>

namespace silkrpc::ethdb {

class Transaction {
public:
    Transaction() = default;

    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;

    virtual ~Transaction() = default;

    virtual uint64_t tx_id() const = 0;

    virtual boost::asio::awaitable<void> open() = 0;

    virtual boost::asio::awaitable<std::shared_ptr<Cursor>> cursor(const std::string& table) = 0;

    virtual boost::asio::awaitable<std::shared_ptr<CursorDupSort>> cursor_dup_sort(const std::string& table) = 0;

    virtual boost::asio::awaitable<void> close() = 0;
};

} // namespace silkrpc::ethdb
