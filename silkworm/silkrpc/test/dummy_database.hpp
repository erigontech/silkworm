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

#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/ethdb/cursor.hpp>
#include <silkworm/silkrpc/ethdb/database.hpp>
#include <silkworm/silkrpc/ethdb/transaction.hpp>
#include <silkworm/silkrpc/test/dummy_transaction.hpp>

namespace silkrpc::test {

//! This dummy database acts as a factory for dummy transactions using the same cursor.
class DummyDatabase : public ethdb::Database {
public:
    explicit DummyDatabase(std::shared_ptr<ethdb::Cursor> cursor) : cursor_(cursor) {}

    boost::asio::awaitable<std::unique_ptr<ethdb::Transaction>> begin() override {
        co_return std::make_unique<DummyTransaction>(cursor_);
    }
private:
    std::shared_ptr<ethdb::Cursor> cursor_;
};

}  // namespace silkrpc::test

