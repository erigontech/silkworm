/*
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "config.hpp"

#include <string_view>

#include <catch2/catch.hpp>
#include <magic_enum.hpp>

#include <silkworm/node/snapshot/config_toml.hpp>
#include <silkworm/node/snapshot/path.hpp>

namespace silkworm::snapshot {

TEST_CASE("from_toml", "[silkworm][snapshot][from_toml]") {
    SECTION("invalid") {
        const std::string_view kInvalidSnapshotTomlData[]{
            "'v1-000000-000500-bodies.seg' = b3a879e769292f526282cf92398d892fac090198",
            "'v1-000000-000500-bodies.seg' 'b3a879e769292f526282cf92398d892fac090198'",
        };
        for (const auto& snapshot_toml_data : kInvalidSnapshotTomlData) {
            CHECK_THROWS_AS(from_toml(snapshot_toml_data), std::exception);
        }
    }

    SECTION("valid") {
        const std::string_view kValidSnapshotTomlData[]{
            {bor_mainnet_toml_data(), bor_mainnet_toml_size()},
            {chiado_toml_data(), chiado_toml_size()},
            {gnosis_toml_data(), gnosis_toml_size()},
            {goerli_toml_data(), goerli_toml_size()},
            {mainnet_toml_data(), mainnet_toml_size()},
            {mumbai_toml_data(), mumbai_toml_size()},
            {ropsten_toml_data(), ropsten_toml_size()},
            {sepolia_toml_data(), sepolia_toml_size()},
        };
        for (const auto& snapshot_toml_data : kValidSnapshotTomlData) {
            CHECK_NOTHROW(from_toml(snapshot_toml_data));
        }
    }
}

TEST_CASE("Config::lookup_known_config", "[silkworm][snapshot][config]") {
    SECTION("nonexistent") {
        const auto nonexistent_snapshot_config = Config::lookup_known_config(0, {});
        CHECK(nonexistent_snapshot_config->preverified_snapshots().empty());
        CHECK(nonexistent_snapshot_config->max_block_number() == 0);
    }

    SECTION("mainnet") {
        constexpr std::size_t kExpectedMaxBlockNumber{18'000'000};
        const int kSnapshotSegmentCount{magic_enum::enum_count<SnapshotType>() - 1};  // transactions2block has no segments
        const auto mainnet_snapshot_config = Config::lookup_known_config(1, {});
        CHECK(mainnet_snapshot_config->preverified_snapshots().size() ==
              kSnapshotSegmentCount * kExpectedMaxBlockNumber / kDefaultSegmentSize);
        CHECK(mainnet_snapshot_config->max_block_number() == kExpectedMaxBlockNumber - 1);
    }
}

TEST_CASE("Config", "[silkworm][snapshot][config]") {
    SECTION("empty") {
        Config cfg{{}};
        CHECK(cfg.preverified_snapshots().empty());
        CHECK(cfg.max_block_number() == 0);
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
        CHECK(cfg.max_block_number() == 14'500'000 - 1);
    }
}

}  // namespace silkworm::snapshot
