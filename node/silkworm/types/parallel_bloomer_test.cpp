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

#include "parallel_bloomer.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/util.hpp>

namespace silkworm {

TEST_CASE("Parallel Bloom") {
    static const std::vector<Log> logs{
        {
            0x22341ae42d6dd7384bc8584e50419ea3ac75b83f_address,                            // address
            {0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32},  // topics
            *from_hex("0x2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7b"),   // data
        },
        {
            0xe7fb22dfef11920312e4989a3a2b81e2ebf05986_address,  // address
            {
                0x7f1fef85c4b037150d3675218e0cdb7cf38fea354759471e309f3354918a442f_bytes32,
                0xd85629c7eaae9ea4a10234fed31bc0aeda29b2683ebe0c1882499d272621f6b6_bytes32,
                0x46bc8b9dd25fe31282513ddb3567822730c2211dbbdc0ac40072ade150e8d866_bytes32,
                0x114790e3f9d77c50c130cf82c4e5d9d0428c3da90a9a2b918bad22ac8789c9cb_bytes32,
                0xdc12b67aafcd8d164badb9ae87116ed36ffa8201c2d36318291eac2abe64b940_bytes32,
                0x114790e3f9d77c50c130cf82c4e5d9d0428c3da90a9a2b918bad22ac8789c9cb_bytes32,
                0x354cf792e31da0459886ac279ad4629de4705baf2126ab9adfad81d358203e74_bytes32,
                0x1a03cf40147ecc3a82394eb43c626c837639b1c91425a857c233d8936ad8e34c_bytes32,
            },  // topics
        },
        {
            0xe7592aefb6d17a6938ccdb1d39e8f1d27ca0255e_address,  // address
            {},                                                  // topics
        },
    };

    LogsBloomer serial_bloomer;
    Bloom serial_bloom{serial_bloomer.bloom_filter(logs)};

    ParallelBloomer parallel_bloomer;
    Bloom parallel_bloom{parallel_bloomer.bloom_filter(logs)};

    CHECK(parallel_bloom == serial_bloom);
}

}  // namespace silkworm
