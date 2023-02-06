/*
   Copyright 2023 The Silkworm Authors

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

#include <silkworm/snapshot/config_toml.hpp>

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
            {bsc_toml_data(), bsc_toml_size()},
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

}  // namespace silkworm::snapshot
