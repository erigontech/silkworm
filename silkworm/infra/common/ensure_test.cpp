// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ensure.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>

namespace silkworm {

using Catch::Matchers::Message;

TEST_CASE("ensure") {
    CHECK_NOTHROW(ensure(true, "ignored"));
    CHECK_THROWS_AS(ensure(false, "error"), std::logic_error);
    CHECK_THROWS_MATCHES(ensure(false, "condition violation"), std::logic_error, Message("condition violation"));
}

TEST_CASE("ensure dynamic message") {
    CHECK_NOTHROW(ensure(true, []() { return "ignored"; }));
    CHECK_THROWS_AS(ensure(false, []() { return "error"; }), std::logic_error);
    CHECK_THROWS_MATCHES(ensure(false, []() { return "condition violation"; }), std::logic_error, Message("condition violation"));
    CHECK_THROWS_MATCHES(ensure(false, []() { return "condition violation " + std::to_string(42); }), std::logic_error, Message("condition violation 42"));
}

TEST_CASE("ensure_invariant") {
    CHECK_NOTHROW(ensure_invariant(true, "ignored"));
    CHECK_THROWS_AS(ensure_invariant(false, "error"), std::logic_error);
    CHECK_THROWS_MATCHES(ensure_invariant(false, "x"), std::logic_error, Message("Invariant violation: x"));
}

TEST_CASE("ensure_invariant dynamic message") {
    CHECK_NOTHROW(ensure_invariant(true, []() { return "ignored"; }));
    CHECK_THROWS_AS(ensure_invariant(false, []() { return "error"; }), std::logic_error);
    CHECK_THROWS_MATCHES(ensure_invariant(false, []() { return "x"; }), std::logic_error, Message("Invariant violation: x"));
    CHECK_THROWS_MATCHES(ensure_invariant(false, []() { return "x " + std::to_string(42); }), std::logic_error, Message("Invariant violation: x 42"));
}

TEST_CASE("ensure_pre_condition") {
    CHECK_NOTHROW(ensure_pre_condition(true, []() { return "ignored"; }));
    CHECK_THROWS_AS(ensure_pre_condition(false, []() { return "error"; }), std::logic_error);
    CHECK_THROWS_MATCHES(ensure_pre_condition(false, []() { return "x"; }), std::logic_error, Message("Pre-condition violation: x"));
    CHECK_THROWS_MATCHES(ensure_pre_condition(false, []() { return "x " + std::to_string(42); }), std::logic_error, Message("Pre-condition violation: x 42"));
}

TEST_CASE("ensure_post_condition") {
    CHECK_NOTHROW(ensure_post_condition(true, []() { return "ignored"; }));
    CHECK_THROWS_AS(ensure_post_condition(false, []() { return "error"; }), std::logic_error);
    CHECK_THROWS_MATCHES(ensure_post_condition(false, []() { return "x"; }), std::logic_error, Message("Post-condition violation: x"));
    CHECK_THROWS_MATCHES(ensure_post_condition(false, []() { return "x " + std::to_string(42); }), std::logic_error, Message("Post-condition violation: x 42"));
}

}  // namespace silkworm