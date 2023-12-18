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
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <gmock/gmock.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/ethdb/cursor.hpp>
#include <silkworm/rpc/ethdb/transaction.hpp>

namespace silkworm::rpc::test {

class MockTransaction : public ethdb::Transaction {
  public:
    MOCK_METHOD(uint64_t, view_id, (), (const));
    MOCK_METHOD((Task<void>), open, ());
    MOCK_METHOD((Task<std::shared_ptr<ethdb::Cursor>>), cursor, (const std::string&));
    MOCK_METHOD((Task<std::shared_ptr<ethdb::CursorDupSort>>), cursor_dup_sort, (const std::string&));
    MOCK_METHOD((std::shared_ptr<silkworm::State>), create_state,
                (boost::asio::any_io_executor&, const core::rawdb::DatabaseReader&, const ChainStorage&, BlockNum));
    MOCK_METHOD((std::shared_ptr<ChainStorage>), create_storage,
                (const core::rawdb::DatabaseReader&, ethbackend::BackEnd*));
    MOCK_METHOD((Task<void>), close, ());
};

}  // namespace silkworm::rpc::test
