// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "stages.hpp"

#include <string>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch_test_macros.hpp>
#include <gmock/gmock.h>

#include <silkworm/db/kv/api/endpoint/key_value.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/test_util/mock_transaction.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>

namespace silkworm::rpc::stages {

using db::kv::api::KeyValue;
using testing::_;
using testing::InvokeWithoutArgs;

TEST_CASE("get_sync_stage_progress", "[rpc][stagedsync]") {
    WorkerPool pool{1};
    db::test_util::MockTransaction transaction;

    SECTION("empty stage key") {
        EXPECT_CALL(transaction, get(db::table::kSyncStageProgressName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, silkworm::Bytes{}};
        }));
        auto result = boost::asio::co_spawn(pool, get_sync_stage_progress(transaction, kFinish), boost::asio::use_future);
        CHECK(result.get() == 0);
    }

    SECTION("invalid stage progress value") {
        EXPECT_CALL(transaction, get(db::table::kSyncStageProgressName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("FF")};
        }));
        auto result = boost::asio::co_spawn(pool, get_sync_stage_progress(transaction, kFinish), boost::asio::use_future);
        CHECK_THROWS_AS(result.get(), std::runtime_error);
    }

    SECTION("valid stage progress value") {
        EXPECT_CALL(transaction, get(db::table::kSyncStageProgressName, _)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{silkworm::Bytes{}, *silkworm::from_hex("00000000000000FF")};
        }));
        auto result = boost::asio::co_spawn(pool, get_sync_stage_progress(transaction, kFinish), boost::asio::use_future);
        CHECK(result.get() == 255);
    }
}

}  // namespace silkworm::rpc::stages
