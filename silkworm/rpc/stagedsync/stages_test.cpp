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

#include "stages.hpp"

#include <string>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch.hpp>
#include <gmock/gmock.h>

#include <silkworm/db/tables.hpp>
#include <silkworm/rpc/test/mock_database_reader.hpp>

namespace silkworm::rpc::stages {

using testing::_;
using testing::InvokeWithoutArgs;

TEST_CASE("get_sync_stage_progress", "[rpc][stagedsync]") {
    boost::asio::thread_pool pool{1};
    test::MockDatabaseReader db_reader;

    SECTION("empty stage key") {
        EXPECT_CALL(db_reader, get(db::table::kSyncStageProgressName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> { co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}}; }));
        auto result = boost::asio::co_spawn(pool, get_sync_stage_progress(db_reader, kFinish), boost::asio::use_future);
        CHECK(result.get() == 0);
    }

    SECTION("invalid stage progress value") {
        EXPECT_CALL(db_reader, get(db::table::kSyncStageProgressName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> { co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("FF")}; }));
        auto result = boost::asio::co_spawn(pool, get_sync_stage_progress(db_reader, kFinish), boost::asio::use_future);
        CHECK_THROWS_AS(result.get(), std::runtime_error);
    }

    SECTION("valid stage progress value") {
        EXPECT_CALL(db_reader, get(db::table::kSyncStageProgressName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> { co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("00000000000000FF")}; }));
        auto result = boost::asio::co_spawn(pool, get_sync_stage_progress(db_reader, kFinish), boost::asio::use_future);
        CHECK(result.get() == 255);
    }
}

}  // namespace silkworm::rpc::stages
