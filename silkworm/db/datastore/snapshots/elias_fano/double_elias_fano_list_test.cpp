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

#include "double_elias_fano_list.hpp"

#include <sstream>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/util.hpp>

namespace silkworm::snapshots::elias_fano {

using silkworm::snapshots::encoding::Uint64Sequence;

TEST_CASE("DoubleEliasFanoList16", "[silkworm][recsplit][elias_fano]") {
    DoubleEliasFanoList16 double_ef_list;
    std::vector<uint64_t> cum_keys{1, 1, 2, 6, 7, 11, 13, 20};
    std::vector<uint64_t> position{1, 2, 5, 5, 6, 7, 9, 9};
    double_ef_list.build(cum_keys, position);

    CHECK(double_ef_list.num_buckets() == cum_keys.size() - 1);

    for (uint64_t i{0}; i < double_ef_list.num_buckets(); ++i) {
        uint64_t x{0}, x2{0}, y{0};

        double_ef_list.get3(i, x, x2, y);
        CHECK(x == cum_keys[i]);
        CHECK(x2 == cum_keys[i + 1]);
        CHECK(y == position[i]);

        double_ef_list.get2(i, x, y);
        CHECK(x == cum_keys[i]);
        CHECK(y == position[i]);
    }

    CHECK(double_ef_list.data() == Uint64Sequence{0x73, 0x0, 0x214cb, 0x1958a, 0x0, 0x1, 0x0, 0x0});

    std::stringstream str_stream;
    str_stream << double_ef_list;
    const std::string stream = str_stream.str();
    CHECK(Bytes{stream.cbegin(), stream.cend()} ==
          *from_hex("0000000000000007"  // num_buckets
                    "0000000000000015"  // u_cum_keys
                    "000000000000000a"  // u_position
                    "0000000000000000"  // cum_keys_min_delta
                    "0000000000000000"  // position_min_delta
                    "73000000000000000000000000000000cb140200000000008a95010000000000"
                    "0000000000000000010000000000000000000000000000000000000000000000"));
}

}  // namespace silkworm::snapshots::elias_fano
