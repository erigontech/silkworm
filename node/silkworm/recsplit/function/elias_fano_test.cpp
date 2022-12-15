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

#include <utility>

#include <catch2/catch.hpp>

#include <silkworm/test/log.hpp>
#include <silkworm/test/snapshot_files.hpp>

namespace silkworm {

using DoubleEliasFanoList = sux::function::DoubleEliasFanoList<>;
class DoubleEliasFanoList_ForTest : public DoubleEliasFanoList {
  public:
    using DoubleEliasFanoList::DoubleEliasFanoList;
    using DoubleEliasFanoList::num_buckets;
    using DoubleEliasFanoList::get3;
    using DoubleEliasFanoList::get2;
};

TEST_CASE("DoubleEliasFanoList::build", "[silkworm][recsplit][elias_fano]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    DoubleEliasFanoList_ForTest double_ef_list;
    std::vector<uint64_t> cum_keys{1, 1, 2, 6, 7, 11, 13, 20};
    std::vector<uint64_t> position{1, 2, 5, 5, 6, 7, 9, 9};
    double_ef_list.build(cum_keys, position);

    for (uint64_t i{0}; i < double_ef_list.num_buckets(); i++) {
        uint64_t x, x2, y;

        double_ef_list.get3(i, x, x2, y);
        // CHECK(x == cum_keys[i]);
        // CHECK(x2 ==cum_keys[i + 1]);
        CHECK(y == position[i]);

        double_ef_list.get2(i, x, y);
        // CHECK(x == cum_keys[i]);
        CHECK(y == position[i]);
    }
}

}  // namespace silkworm
