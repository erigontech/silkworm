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
    MOCK_METHOD(uint64_t, tx_id, (), (const, override));
    MOCK_METHOD(uint64_t, view_id, (), (const, override));
    MOCK_METHOD(void, set_state_cache_enabled, (bool), (override));
    MOCK_METHOD((Task<void>), open, (), (override));
    MOCK_METHOD((Task<std::shared_ptr<ethdb::Cursor>>), cursor, (const std::string&), (override));
    MOCK_METHOD((Task<std::shared_ptr<ethdb::CursorDupSort>>), cursor_dup_sort, (const std::string&), (override));
    MOCK_METHOD((std::shared_ptr<silkworm::State>), create_state,
                (boost::asio::any_io_executor&, const ChainStorage&, BlockNum), (override));
    MOCK_METHOD((std::shared_ptr<ChainStorage>), create_storage, (), (override));
    MOCK_METHOD((Task<void>), close, (), (override));
    MOCK_METHOD((Task<KeyValue>), get, (const std::string&, silkworm::ByteView), (override));
    MOCK_METHOD((Task<silkworm::Bytes>), get_one, (const std::string&, silkworm::ByteView), (override));
    MOCK_METHOD((Task<std::optional<silkworm::Bytes>>), get_both_range,
                (const std::string&, silkworm::ByteView, silkworm::ByteView), (override));
};

}  // namespace silkworm::rpc::test
