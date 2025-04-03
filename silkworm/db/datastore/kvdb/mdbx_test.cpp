// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "mdbx.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::datastore::kvdb {

TEST_CASE("open_env") {
    // Empty dir
    std::string empty{};
    EnvConfig db_config{empty};
    db_config.in_memory = true;
    REQUIRE_THROWS_AS(open_env(db_config), std::invalid_argument);

    // Conflicting flags
    TemporaryDirectory tmp_dir1;
    DataDirectory data_dir{tmp_dir1.path()};
    REQUIRE_NOTHROW(data_dir.deploy());
    REQUIRE(data_dir.exists());

    db_config.path = data_dir.chaindata().path().string();
    db_config.create = true;
    db_config.shared = true;
    REQUIRE_THROWS_AS(open_env(db_config), std::runtime_error);

    // Must open
    db_config.shared = false;
    ::mdbx::env_managed env;
    REQUIRE_NOTHROW(env = open_env(db_config));

    // Create in same path not allowed
    ::mdbx::env_managed env2;
    REQUIRE_THROWS(env2 = open_env(db_config));

    env.close();

    // Conflicting flags
    TemporaryDirectory tmp_dir2;
    db_config = EnvConfig{tmp_dir2.path().string()};
    db_config.create = true;
    db_config.readonly = true;
    db_config.in_memory = true;
    REQUIRE_THROWS_AS(open_env(db_config), std::runtime_error);

    // Must open
    db_config.readonly = false;
    db_config.exclusive = true;
    REQUIRE_NOTHROW(env = open_env(db_config));
    env.close();
}

}  // namespace silkworm::datastore::kvdb
