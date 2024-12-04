/*
   Copyright 2024 The Silkworm Authors

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

#include "mdbx.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::sw_mdbx {

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

}  // namespace silkworm::sw_mdbx
