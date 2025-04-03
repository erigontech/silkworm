// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "kv_calls.hpp"

#include <string>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/common/directories.hpp>

namespace silkworm::db::kv::grpc::server {

TEST_CASE("higher_version_ignoring_patch", "[silkworm][rpc][kv_calls]") {
    SECTION("lhs.major > rhs.major") {
        api::Version lhs{2, 0, 0};
        api::Version rhs{1, 0, 0};
        CHECK(higher_version_ignoring_patch(lhs, rhs) == lhs);
    }

    SECTION("rhs.major > lhs.major") {
        api::Version lhs{2, 0, 0};
        api::Version rhs{3, 0, 0};
        CHECK(higher_version_ignoring_patch(lhs, rhs) == rhs);
    }

    SECTION("lhs.minor > rhs.minor") {
        api::Version lhs{2, 5, 0};
        api::Version rhs{2, 2, 0};
        CHECK(higher_version_ignoring_patch(lhs, rhs) == lhs);
    }

    SECTION("rhs.minor > lhs.minor") {
        api::Version lhs{2, 5, 0};
        api::Version rhs{2, 6, 0};
        CHECK(higher_version_ignoring_patch(lhs, rhs) == rhs);
    }

    SECTION("patch not relevant") {
        api::Version lhs1{2, 5, 0};
        api::Version rhs1{2, 5, 0};
        CHECK(higher_version_ignoring_patch(lhs1, rhs1) == lhs1);
        api::Version lhs2{2, 5, 1};
        api::Version rhs2{2, 5, 0};
        CHECK(higher_version_ignoring_patch(lhs2, rhs2) == lhs2);
        api::Version lhs3{2, 5, 0};
        api::Version rhs3{2, 5, 1};
        CHECK(higher_version_ignoring_patch(lhs3, rhs3) == lhs3);
    }
}

static const datastore::kvdb::MapConfig kTestMap{"TestTable"};

TEST_CASE("dump_mdbx_result", "[silkworm][rpc][kv_calls]") {
    using namespace silkworm::datastore::kvdb;

    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};
    REQUIRE_NOTHROW(data_dir.deploy());
    EnvConfig db_config;
    db_config.path = data_dir.chaindata().path().string();
    db_config.create = true;
    db_config.in_memory = true;
    auto database_env = open_env(db_config);
    auto rw_txn{database_env.start_write()};
    open_map(rw_txn, kTestMap);
    PooledCursor rw_cursor{rw_txn, kTestMap};
    rw_cursor.upsert(mdbx::slice{"AA"}, mdbx::slice{"00"});
    rw_cursor.upsert(mdbx::slice{"BB"}, mdbx::slice{"11"});
    rw_txn.commit();

    auto ro_txn = database_env.start_read();
    PooledCursor cursor{ro_txn, kTestMap};
    CursorResult result = cursor.to_first(/*throw_notfound=*/false);
    const auto result_dump = datastore::kvdb::detail::dump_mdbx_result(result);
    CHECK(result_dump.find(std::to_string(result.done)) != std::string::npos);
    CHECK(result_dump.find(std::to_string(static_cast<bool>(result.key))) != std::string::npos);
    CHECK(result_dump.find(std::to_string(static_cast<bool>(result.value))) != std::string::npos);
    ro_txn.abort();
}

}  // namespace silkworm::db::kv::grpc::server
