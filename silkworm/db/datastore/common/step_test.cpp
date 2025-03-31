// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "step.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm::datastore {

TEST_CASE("Step", "[datastore][common]") {
    SECTION("Step constructor and value") {
        Step step{10};
        CHECK(step.value == 10);
    }

    SECTION("Step comparison operators") {
        Step step1{10};
        Step step2{20};

        CHECK(step1 < step2);
        CHECK(step1 <= step2);
        CHECK_FALSE(step2 < step1);
    }

    SECTION("Step to string") {
        Step step{100};
        CHECK(step.to_string() == "100st");
    }
}

TEST_CASE("StepRange", "[datastore][common]") {
    StepRange range(Step{10}, Step{20});

    SECTION("StepRange constructor") {
        CHECK(range.start.value == 10);
        CHECK(range.end.value == 20);
    }

    SECTION("StepRange containment") {
        CHECK(range.contains(Step{15}));
        CHECK_FALSE(range.contains(Step{25}));
    }

    SECTION("StepRange size") {
        CHECK(range.size() == 10);
    }

    SECTION("StepRange to string") {
        CHECK(range.to_string() == "[10st, 20st)");
    }
}

}  // namespace silkworm::datastore
