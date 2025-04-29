// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "server_settings.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/concurrency/context_pool_settings.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc {

// Exclude gRPC tests from sanitizer builds due to data race warnings inside gRPC library
#ifndef SILKWORM_SANITIZE
TEST_CASE("ServerConfig::ServerConfig", "[silkworm][rpc][server_settings]") {
    ServerSettings config;
    CHECK(config.address_uri == std::string{kDefaultAddressUri});
    CHECK(config.context_pool_settings.num_contexts > 0);
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc
