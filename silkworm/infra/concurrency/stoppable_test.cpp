// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/concurrency/stoppable.hpp>

namespace silkworm {

TEST_CASE("Stoppable") {
    silkworm::Stoppable stoppable{};
    REQUIRE(stoppable.is_stopping() == false);
    REQUIRE(stoppable.stop() == true);
    REQUIRE(stoppable.stop() == false);
    REQUIRE(stoppable.is_stopping() == true);
}

}  // namespace silkworm
