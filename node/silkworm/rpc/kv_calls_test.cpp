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

#include <catch2/catch.hpp>

namespace silkworm::rpc {

TEST_CASE("higher_version", "[silkworm][rpc][kv_calls]") {
    SECTION("lhs.major > rhs.major") {
        KvVersion lhs{2, 0, 0};
        KvVersion rhs{1, 0, 0};
        CHECK(higher_version(lhs, rhs) == lhs);
    }

    SECTION("rhs.major > lhs.major") {
        KvVersion lhs{2, 0, 0};
        KvVersion rhs{3, 0, 0};
        CHECK(higher_version(lhs, rhs) == rhs);
    }

    SECTION("lhs.minor > rhs.minor") {
        KvVersion lhs{2, 5, 0};
        KvVersion rhs{2, 2, 0};
        CHECK(higher_version(lhs, rhs) == lhs);
    }

    SECTION("rhs.minor > lhs.minor") {
        KvVersion lhs{2, 5, 0};
        KvVersion rhs{2, 6, 0};
        CHECK(higher_version(lhs, rhs) == rhs);
    }

    SECTION("patch not relevant") {
        KvVersion lhs1{2, 5, 0};
        KvVersion rhs1{2, 5, 0};
        CHECK(higher_version(lhs1, rhs1) == lhs1);
        KvVersion lhs2{2, 5, 1};
        KvVersion rhs2{2, 5, 0};
        CHECK(higher_version(lhs2, rhs2) == lhs2);
        KvVersion lhs3{2, 5, 0};
        KvVersion rhs3{2, 5, 1};
        CHECK(higher_version(lhs3, rhs3) == lhs3);
    }
}

} // namespace silkworm::rpc
