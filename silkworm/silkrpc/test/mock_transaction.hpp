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

#include <memory>
#include <string>

#include <boost/asio/awaitable.hpp>
#include <gmock/gmock.h>
#include <silkworm/core/common/base.hpp>

#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/ethdb/cursor.hpp>
#include <silkworm/silkrpc/ethdb/transaction.hpp>

namespace silkrpc::test {

class MockTransaction : public ethdb::Transaction {
  public:
    MOCK_METHOD(uint64_t, tx_id, (), (const));
    MOCK_METHOD((boost::asio::awaitable<void>), open, ());
    MOCK_METHOD((boost::asio::awaitable<std::shared_ptr<ethdb::Cursor>>), cursor, (const std::string&));
    MOCK_METHOD((boost::asio::awaitable<std::shared_ptr<ethdb::CursorDupSort>>), cursor_dup_sort, (const std::string&));
    MOCK_METHOD((boost::asio::awaitable<void>), close, ());
};

}  // namespace silkrpc::test

