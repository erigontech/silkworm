// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "config.hpp"

#include <string_view>

#include <catch2/catch_test_macros.hpp>

namespace silkworm::snapshots {

TEST_CASE("Config::lookup_known_config", "[silkworm][snapshot][config]") {
    SECTION("nonexistent") {
        const auto cfg = Config::lookup_known_config(0);
        CHECK(cfg.preverified_snapshots().empty());
    }

    SECTION("mainnet") {
        const auto cfg = Config::lookup_known_config(1);
        CHECK_FALSE(cfg.preverified_snapshots().empty());
    }
}

TEST_CASE("Config", "[silkworm][snapshot][config]") {
    SECTION("empty") {
        Config cfg{{}};
        CHECK(cfg.preverified_snapshots().empty());
    }

    SECTION("non-empty") {
        PreverifiedList preverified{
            {"v1-000000-000500-bodies.seg", "e9b5c5d1885ee3c6ab6005919e511e1e04c7e34e"},
            {"v1-000000-000500-headers.seg", "df09957d8a28af3bc5137478885a8003677ca878"},
            {"v1-000000-000500-transactions.seg", "92bb09068baa8eab9d5ad5e69c1eecd404a82258"},
            {"v1-014000-014500-bodies.seg", "70a8b050d1a4abd8424cb8c94d22fff6e58b3fd9"},
            {"v1-014000-014500-headers.seg", "fa45e222c6a01f6090d968cf93d105947dab72cd"},
            {"v1-014000-014500-transactions.seg", "ee3c18488a1d74969c5e75b16f5adceac5dbcd15"},
        };
        Config cfg{preverified};
        CHECK(cfg.preverified_snapshots().size() == preverified.size());
    }
}

}  // namespace silkworm::snapshots
