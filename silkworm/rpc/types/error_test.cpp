// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "error.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/test_util/null_stream.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc {

TEST_CASE("create empty error", "[rpc][types][error]") {
    Error err{};
    CHECK(err.code == 0);
    CHECK(err.message.empty());
}

TEST_CASE("create empty revert error", "[rpc][types][error]") {
    RevertError err{};
    CHECK(err.code == 0);
    CHECK(err.message.empty());
    CHECK(err.data.empty());
}

TEST_CASE("print empty error", "[rpc][types][error]") {
    Error err{};
    CHECK_NOTHROW(silkworm::test_util::null_stream() << err);
}

TEST_CASE("print empty revert error", "[rpc][types][error]") {
    RevertError err{};
    CHECK_NOTHROW(silkworm::test_util::null_stream() << err);
}

}  // namespace silkworm::rpc
