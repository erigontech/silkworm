// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "issuance.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/test_util/null_stream.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc {

TEST_CASE("create empty issuance", "[rpc][types][issuance]") {
    Issuance i{};
    CHECK(i.block_reward == std::nullopt);
    CHECK(i.ommer_reward == std::nullopt);
    CHECK(i.issuance == std::nullopt);
}

TEST_CASE("print empty issuance", "[rpc][types][issuance]") {
    Issuance i{};
    CHECK_NOTHROW(silkworm::test_util::null_stream() << i);
}

}  // namespace silkworm::rpc
