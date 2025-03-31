// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "log.hpp"

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/core/test_util/null_stream.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc {

TEST_CASE("create empty log", "[rpc][types][log]") {
    Log l{};
    CHECK(l.address == evmc::address{});
    CHECK(l.topics.empty());
    CHECK(l.data.empty());
}

TEST_CASE("print empty log", "[rpc][types][log]") {
    Log l{};
    CHECK_NOTHROW(silkworm::test_util::null_stream() << l);
}

}  // namespace silkworm::rpc
