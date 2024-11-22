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

#include "environment.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("Environment") {
    SECTION("set/get stop_at_block") {
        REQUIRE(!Environment::get_stop_at_block().has_value());
        Environment::set_stop_at_block(100);
        REQUIRE(Environment::get_stop_at_block() == 100);
    }

    SECTION("set/get stop_before_stage") {
        REQUIRE(!Environment::get_stop_before_stage().has_value());
        Environment::set_stop_before_stage("stage1");
        REQUIRE(Environment::get_stop_before_stage() == "stage1");
    }

    SECTION("set/get are_pre_verified_hashes_disabled") {
        REQUIRE(!Environment::are_pre_verified_hashes_disabled());
        Environment::set_pre_verified_hashes_disabled();
        REQUIRE(Environment::are_pre_verified_hashes_disabled());
    }

    SECTION("get env var") {
        CHECK(Environment::get("UNEXISTING_ENV_VAR").empty());
        CHECK_FALSE(Environment::get("PATH").empty());
    }
}

}  // namespace silkworm