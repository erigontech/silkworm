// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "trace_api.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc::commands {

#ifndef SILKWORM_SANITIZE
TEST_CASE("TraceRpcApi") {
    boost::asio::io_context ioc;
    WorkerPool workers{1};

    SECTION("CTOR") {
        CHECK_THROWS_AS(TraceRpcApi(ioc, workers), std::logic_error);
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::commands
