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
#include <silkworm/silkrpc/ethdb/transaction.hpp>

namespace silkrpc::test {

//! This dummy transaction just gives you the same cursor over and over again.
class DummyTransaction : public ethdb::Transaction {
public:
    explicit DummyTransaction(uint64_t tx_id, std::shared_ptr<ethdb::CursorDupSort> cursor) : tx_id_(tx_id), cursor_(cursor) {}

    uint64_t tx_id() const override { return tx_id_; }

    boost::asio::awaitable<void> open() override { co_return; }

    boost::asio::awaitable<std::shared_ptr<ethdb::Cursor>> cursor(const std::string& /*table*/) override {
        co_return cursor_;
    }

    boost::asio::awaitable<std::shared_ptr<ethdb::CursorDupSort>> cursor_dup_sort(const std::string& /*table*/) override {
        co_return cursor_;
    }

    boost::asio::awaitable<void> close() override { co_return; }

private:
    uint64_t tx_id_;
    std::shared_ptr<ethdb::CursorDupSort> cursor_;
};

}  // namespace silkrpc::test

