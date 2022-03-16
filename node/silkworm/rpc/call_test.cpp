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

#include "call.hpp"

#include <catch2/catch.hpp>

namespace silkworm::rpc {

TEST_CASE("BaseRpc", "[silkworm][rpc][call]") {
    class FakeRpc : public BaseRpc {
      protected:
        void cleanup() override {}
    };

    SECTION("count live instances") {
        REQUIRE(BaseRpc::instance_count() == 0);
        {
            FakeRpc rpc1;
            CHECK(BaseRpc::instance_count() == 1);
        }
        REQUIRE(BaseRpc::instance_count() == 0);
        {
            FakeRpc rpc1;
            CHECK(BaseRpc::instance_count() == 1);
            FakeRpc rpc2;
            CHECK(BaseRpc::instance_count() == 2);
        }
        REQUIRE(BaseRpc::instance_count() == 0);
    }

    SECTION("count total instances") {
        FakeRpc rpc;
        CHECK(BaseRpc::total_count() > 0);
    }
}

} // namespace silkworm::rpc
