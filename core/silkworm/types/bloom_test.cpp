/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "bloom.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/util.hpp>

namespace silkworm {
TEST_CASE("Hardcoded Bloom") {
    std::vector<Log> logs{
        {
            0x22341ae42d6dd7384bc8584e50419ea3ac75b83f_address,                            // address
            {0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32},  // topics
        },
        {
            0xe7fb22dfef11920312e4989a3a2b81e2ebf05986_address,  // address
            {
                0x7f1fef85c4b037150d3675218e0cdb7cf38fea354759471e309f3354918a442f_bytes32,
                0xd85629c7eaae9ea4a10234fed31bc0aeda29b2683ebe0c1882499d272621f6b6_bytes32,
            },                                                                            // topics
            *from_hex("0x2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7b"),  // data
        },
    };
    Bloom bloom{logs_bloom(logs)};
    CHECK(to_hex(full_view(bloom)) ==
          "000000000000000000810000000000000000000000000000000000020000000000000000000000000000008000"
          "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
          "000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000"
          "000000000000000000000000000000000000000000000000000000280000000000400000800000004000000000"
          "000000000000000000000000000000000000000000000000000000000000100000100000000000000000000000"
          "00000000001400000000000000008000000000000000000000000000000000");
}
}  // namespace silkworm
