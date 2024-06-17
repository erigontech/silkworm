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

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc {

TEST_CASE("BaseRpc", "[silkworm][rpc][call][.]") {
    class FakeRpc : public server::Call {
      public:
        explicit FakeRpc(grpc::ServerContext& server_context) : server::Call(server_context) {}
    };

    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    grpc::ServerContext server_context;

    SECTION("count live instances") {
        REQUIRE(FakeRpc::instance_count() == 0);
        {
            FakeRpc rpc1{server_context};
            CHECK(FakeRpc::instance_count() == 1);
        }
        REQUIRE(FakeRpc::instance_count() == 0);
        {
            FakeRpc rpc1{server_context};
            CHECK(FakeRpc::instance_count() == 1);
            FakeRpc rpc2{server_context};
            CHECK(FakeRpc::instance_count() == 2);
        }
        REQUIRE(FakeRpc::instance_count() == 0);
    }

    SECTION("count total instances") {
        FakeRpc rpc{server_context};
        CHECK(FakeRpc::total_count() > 0);
    }

    SECTION("peer") {
        FakeRpc rpc{server_context};
        CHECK(rpc.peer().empty());
    }
}

}  // namespace silkworm::rpc
