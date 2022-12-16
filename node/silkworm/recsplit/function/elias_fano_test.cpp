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

#include "elias_fano.hpp"

#include <algorithm>
#include <utility>

#include <catch2/catch.hpp>

#include <silkworm/test/log.hpp>

namespace silkworm {

using EliasFanoList32 = sux::function::EliasFanoList32<>;
class EliasFanoList32_ForTest : public EliasFanoList32 {
  public:
    using EliasFanoList32::EliasFanoList32;
    using EliasFanoList32::get;
};

using DoubleEliasFanoList16 = sux::function::DoubleEliasFanoList16<>;
class DoubleEliasFanoList16_ForTest : public DoubleEliasFanoList16 {
  public:
    using DoubleEliasFanoList16::DoubleEliasFanoList16;
    using DoubleEliasFanoList16::get2;
    using DoubleEliasFanoList16::get3;
    using DoubleEliasFanoList16::num_buckets;
};

TEST_CASE("EliasFanoList32", "[silkworm][recsplit][elias_fano]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};

    std::vector<uint64_t> offsets{1, 4, 6, 8, 10, 14, 16, 19, 22, 34, 37, 39, 41, 43, 48, 51, 54, 58, 62};
    uint64_t max_offset = *std::max_element(offsets.cbegin(), offsets.cend());
    EliasFanoList32_ForTest ef_list{offsets.size(), max_offset};
    for (const auto offset : offsets) {
        ef_list.add_offset(offset);
    }
    ef_list.build();

    CHECK(ef_list.count() == offsets.size());

    for (uint64_t i{0}; i < offsets.size(); i++) {
        const uint64_t x = ef_list.get(i);
        CHECK(x == offsets[i]);
    }
}

TEST_CASE("DoubleEliasFanoList::build", "[silkworm][recsplit][elias_fano]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    DoubleEliasFanoList16_ForTest double_ef_list;
    std::vector<uint64_t> cum_keys{1, 1, 2, 6, 7, 11, 13, 20};
    std::vector<uint64_t> position{1, 2, 5, 5, 6, 7, 9, 9};
    double_ef_list.build(cum_keys, position);

    for (uint64_t i{0}; i < double_ef_list.num_buckets(); i++) {
        uint64_t x, x2, y;

        double_ef_list.get3(i, x, x2, y);
        CHECK(x == cum_keys[i]);
        CHECK(x2 == cum_keys[i + 1]);
        CHECK(y == position[i]);

        double_ef_list.get2(i, x, y);
        CHECK(x == cum_keys[i]);
        CHECK(y == position[i]);
    }
}

}  // namespace silkworm
