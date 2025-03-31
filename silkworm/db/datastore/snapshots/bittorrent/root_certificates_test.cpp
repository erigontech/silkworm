// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "root_certificates.hpp"

#include <boost/system/system_error.hpp>
#include <catch2/catch_test_macros.hpp>

namespace silkworm::snapshots::bittorrent {

TEST_CASE("load_root_certificates", "[db][snapshot][bittorrent]") {
    ssl::context ssl_ctx{ssl::context::tlsv13_client};
    CHECK_NOTHROW(load_root_certificates(ssl_ctx));
}

}  // namespace silkworm::snapshots::bittorrent
