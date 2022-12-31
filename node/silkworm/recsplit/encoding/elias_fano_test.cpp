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
#include <sstream>
#include <utility>

#include <catch2/catch.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/test/log.hpp>

namespace silkworm::succinct {

TEST_CASE("EliasFanoList32", "[silkworm][recsplit][elias_fano]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};

    std::vector<uint64_t> offsets{1, 4, 6, 8, 10, 14, 16, 19, 22, 34, 37, 39, 41, 43, 48, 51, 54, 58, 62};
    uint64_t max_offset = *std::max_element(offsets.cbegin(), offsets.cend());
    EliasFanoList32 ef_list{offsets.size(), max_offset};
    for (const auto offset : offsets) {
        ef_list.add_offset(offset);
    }
    ef_list.build();

    CHECK(ef_list.min() == offsets.at(0));
    CHECK(ef_list.max() == max_offset);
    CHECK(ef_list.count() == offsets.size());

    for (uint64_t i{0}; i < offsets.size(); i++) {
        const uint64_t x = ef_list.get(i);
        CHECK(x == offsets[i]);
    }

    CHECK(ef_list.data() == Uint64Sequence{0xbc81, 0x0, 0x24945540952a9, 0x0, 0x0, 0x0});

    std::stringstream str_stream;
    str_stream << ef_list;
    const std::string stream = str_stream.str();
    CHECK(Bytes{stream.cbegin(), stream.cend()} ==
          *from_hex("0000000000000012"  // count
                    "000000000000003f"  // u
                    "81bc0000000000000000000000000000a952095445490200000000000000000000000000000000000000000000000000"));
}

TEST_CASE("DoubleEliasFanoList16", "[silkworm][recsplit][elias_fano]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    DoubleEliasFanoList16 double_ef_list;
    std::vector<uint64_t> cum_keys{1, 1, 2, 6, 7, 11, 13, 20};
    std::vector<uint64_t> position{1, 2, 5, 5, 6, 7, 9, 9};
    double_ef_list.build(cum_keys, position);

    CHECK(double_ef_list.num_buckets() == cum_keys.size() - 1);

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

}  // namespace silkworm::succinct
