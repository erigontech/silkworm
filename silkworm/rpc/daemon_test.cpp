// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "daemon.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm::rpc {

#ifndef BUILD_COVERAGE
TEST_CASE("DaemonChecklist::success_or_throw", "[rpc]") {
    DaemonChecklist checklist;

    SECTION("empty checklist does not throw") {
        CHECK_NOTHROW(checklist.success_or_throw());
    }

    SECTION("checklist w/ at least one incompatible throws") {
        checklist.protocol_checklist.emplace_back(ProtocolVersionResult{false, ""});
        CHECK_THROWS_AS(checklist.success_or_throw(), std::runtime_error);
    }
}
#endif  // BUILD_COVERAGE

}  // namespace silkworm::rpc
