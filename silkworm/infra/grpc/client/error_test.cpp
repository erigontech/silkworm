// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "error.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("make error code with empty message", "[rpc][grpc][error]") {
    std::error_code error_code{make_error_code(123, "")};
    CHECK(error_code.value() == 123);
    CHECK(error_code.message().empty());
    CHECK(error_code.category().name() == std::string("grpc"));
}

TEST_CASE("make error code with non-empty message", "[rpc][grpc][error]") {
    std::error_code error_code{make_error_code(-123, "undefined error")};
    CHECK(error_code.value() == -123);
    CHECK(error_code.message() == "undefined error");
    CHECK(error_code.category().name() == std::string("grpc"));
}

}  // namespace silkworm
