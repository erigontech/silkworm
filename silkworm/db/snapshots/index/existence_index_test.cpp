/*
   Copyright 2024 The Silkworm Authors

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

#include "existence_index.hpp"

#include <random>
#include <stdexcept>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/db/snapshots/test_util/sample_bloom_filter_data.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/test_util/temporary_file.hpp>

namespace silkworm::snapshots::index {

using silkworm::test_util::TemporaryFile;

TEST_CASE("ExistenceIndex", "[snapshot][index][existence_index]") {
    SECTION("empty") {
        TemporaryDirectory tmp_dir;
        CHECK_THROWS_AS(ExistenceIndex::Reader(tmp_dir.get_unique_temporary_path()), std::runtime_error);
    }

    SECTION("item present") {
        // Create PRNG to generate pseudo-random hash values
        static std::mt19937_64 rnd_generator{std::random_device{}()};
        std::uniform_int_distribution<uint32_t> u32_distribution;

        // Create sample existence index
        REQUIRE(!test_util::kValidBloomFilters.empty());
        TemporaryFile sample_ei_file;
        sample_ei_file.write(*from_hex(test_util::kValidBloomFilters[0]));

        ExistenceIndex::Reader existence_index{sample_ei_file.path()};
        CHECK(existence_index.path() == sample_ei_file.path());
        for (size_t i = 0; i < 100; ++i) {
            const uint64_t h = u32_distribution(rnd_generator);
            existence_index.add_hash(h);
            CHECK(existence_index.contains_hash(h));
        }
    }
}

}  // namespace silkworm::snapshots::index
