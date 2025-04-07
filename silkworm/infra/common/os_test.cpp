// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "os.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm::os {

TEST_CASE("os::max_file_descriptors", "[silkworm][infra][common][os]") {
    const auto current_max_descriptors = max_file_descriptors();
    CHECK(current_max_descriptors > 0);
}

TEST_CASE("os::set_max_file_descriptors", "[silkworm][infra][common][os]") {
    const auto current_max_descriptors = max_file_descriptors();
    CHECK(set_max_file_descriptors(current_max_descriptors - 1));
}

TEST_CASE("os::page_size", "[silkworm][infra][common][os]") {
    CHECK(page_size() >= 4096);
}

}  // namespace silkworm::os
