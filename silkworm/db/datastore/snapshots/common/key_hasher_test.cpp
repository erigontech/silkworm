// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "key_hasher.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm::snapshots {

TEST_CASE("KeyHasher") {
    CHECK(KeyHasher{0}.hash(*from_hex("CAFEBABE")) == 2809309899937206063u);
    CHECK(KeyHasher{12345}.hash(*from_hex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")) == 17810263873480351644u);
}

}  // namespace silkworm::snapshots
