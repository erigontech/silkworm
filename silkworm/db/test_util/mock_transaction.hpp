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
#include <silkworm/db/chain/chain_storage.hpp>
#include <silkworm/db/kv/api/cursor.hpp>
#include <silkworm/db/kv/api/transaction.hpp>

namespace silkworm::db::test_util {

class MockTransaction : public kv::api::Transaction {
  public:
    MOCK_METHOD(uint64_t, tx_id, (), (const, override));
    MOCK_METHOD(uint64_t, view_id, (), (const, override));
    MOCK_METHOD(void, set_state_cache_enabled, (bool), (override));
    MOCK_METHOD((Task<void>), open, (), (override));
    MOCK_METHOD((Task<std::shared_ptr<kv::api::Cursor>>), cursor, (const std::string&), (override));
    MOCK_METHOD((Task<std::shared_ptr<kv::api::CursorDupSort>>), cursor_dup_sort, (const std::string&), (override));
    MOCK_METHOD((std::shared_ptr<State>), create_state,
                (boost::asio::any_io_executor&, const chain::ChainStorage&, BlockNum), (override));
    MOCK_METHOD((std::shared_ptr<chain::ChainStorage>), create_storage, (), (override));
    MOCK_METHOD((Task<void>), close, (), (override));
    MOCK_METHOD((Task<kv::api::KeyValue>), get, (const std::string&, ByteView), (override));
    MOCK_METHOD((Task<Bytes>), get_one, (const std::string&, ByteView), (override));
    MOCK_METHOD((Task<std::optional<Bytes>>), get_both_range,
                (const std::string&, ByteView, ByteView), (override));
    MOCK_METHOD((Task<kv::api::DomainPointResult>), domain_get, (kv::api::DomainPointQuery&&), (override));
    MOCK_METHOD((Task<kv::api::HistoryPointResult>), history_seek, (kv::api::HistoryPointQuery&&), (override));
    MOCK_METHOD((Task<kv::api::PaginatedTimestamps>), index_range, (kv::api::IndexRangeQuery&&), (override));
    MOCK_METHOD((Task<kv::api::PaginatedKeysValues>), history_range, (kv::api::HistoryRangeQuery&&), (override));
    MOCK_METHOD((Task<kv::api::PaginatedKeysValues>), domain_range, (kv::api::DomainRangeQuery&&), (override));
};

}  // namespace silkworm::db::test_util
