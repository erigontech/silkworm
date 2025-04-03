// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "web3_api.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm::rpc::commands {

#ifndef SILKWORM_SANITIZE
TEST_CASE("Web3RpcApi::Web3RpcApi", "[rpc][erigon_api]") {
    boost::asio::io_context ioc;
    CHECK_THROWS_AS(Web3RpcApi(ioc), std::logic_error);
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::commands
