// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "call.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc {

TEST_CASE("BaseRpc", "[silkworm][rpc][call][.]") {
    class FakeRpc : public server::Call {
      public:
        explicit FakeRpc(grpc::ServerContext& server_context) : server::Call(server_context) {}
    };

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
