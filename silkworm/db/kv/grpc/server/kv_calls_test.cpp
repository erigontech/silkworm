/*
   Copyright 2022 The Silkworm Authors

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

#include "kv_calls.hpp"

#include <string>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/common/directories.hpp>

namespace silkworm::kv::grpc::server {

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

static const silkworm::db::MapConfig kTestMap{"TestTable"};

TEST_CASE("dump_mdbx_result", "[silkworm][rpc][kv_calls]") {
    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};
    REQUIRE_NOTHROW(data_dir.deploy());
    db::EnvConfig db_config;
    db_config.path = data_dir.chaindata().path().string();
    db_config.create = true;
    db_config.in_memory = true;
    auto database_env = db::open_env(db_config);
    auto rw_txn{database_env.start_write()};
    db::open_map(rw_txn, kTestMap);
    db::PooledCursor rw_cursor{rw_txn, kTestMap};
    rw_cursor.upsert(mdbx::slice{"AA"}, mdbx::slice{"00"});
    rw_cursor.upsert(mdbx::slice{"BB"}, mdbx::slice{"11"});
    rw_txn.commit();

    auto ro_txn = database_env.start_read();
    db::PooledCursor cursor{ro_txn, kTestMap};
    db::CursorResult result = cursor.to_first(/*throw_notfound=*/false);
    const auto result_dump = db::detail::dump_mdbx_result(result);
    CHECK(result_dump.find(std::to_string(result.done)) != std::string::npos);
    CHECK(result_dump.find(std::to_string(bool(result.key))) != std::string::npos);
    CHECK(result_dump.find(std::to_string(bool(result.value))) != std::string::npos);
    ro_txn.abort();
}

}  // namespace silkworm::kv::grpc::server
