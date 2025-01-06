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

#include "receipt.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/test_util/null_stream.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/types/log.hpp>

namespace silkworm::rpc {

using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

TEST_CASE("create empty receipt", "[rpc][types][receipt]") {
    Receipt r{};
    CHECK(r.success == false);
    CHECK(r.cumulative_gas_used == 0);
    CHECK(r.bloom == silkworm::Bloom{});
}

TEST_CASE("print empty receipt", "[rpc][types][receipt]") {
    Receipt r{};
    CHECK_NOTHROW(silkworm::test_util::null_stream() << r);
}

TEST_CASE("print receipt", "[rpc][types][receipt]") {
    Logs logs{};
    Receipt r{
        TransactionType::kDynamicFee,
        true,
        210000,
        bloom_from_logs(logs),
        logs};
    r.from = 0x0715a7794a1dc8e42615f059dd6e406a6594651a_address;
    r.to = 0x0715a7794a1dc8e42615f059dd6e406a6594651a_address;
    CHECK_NOTHROW(silkworm::test_util::null_stream() << r);
}

TEST_CASE("bloom from empty logs", "[rpc][types][receipt]") {
    Logs logs{};
    CHECK(bloom_from_logs(logs) == silkworm::Bloom{});
}

TEST_CASE("bloom from one empty log", "[rpc][types][receipt]") {
    Logs logs{
        Log{}};
    silkworm::Bloom expected_bloom{};
    expected_bloom[9] = uint8_t{128};
    expected_bloom[47] = uint8_t{2};
    expected_bloom[143] = uint8_t{1};
    CHECK(bloom_from_logs(logs) == expected_bloom);
}

TEST_CASE("bloom from more than one log", "[rpc][types][receipt]") {
    Logs logs{
        {
            0x22341ae42d6dd7384bc8584e50419ea3ac75b83f_address,                            // address
            {0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32},  // topics
        },
        {
            0xe7fb22dfef11920312e4989a3a2b81e2ebf05986_address,  // address
            {
                0x7f1fef85c4b037150d3675218e0cdb7cf38fea354759471e309f3354918a442f_bytes32,
                0xd85629c7eaae9ea4a10234fed31bc0aeda29b2683ebe0c1882499d272621f6b6_bytes32,
            },                                                                                      // topics
            *silkworm::from_hex("0x2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7b"),  // data
        },
    };
    silkworm::Bloom bloom{bloom_from_logs(logs)};
    CHECK(silkworm::to_hex(full_view(bloom)) ==
          "000000000000000000810000000000000000000000000000000000020000000000000000000000000000008000"
          "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
          "000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000"
          "000000000000000000000000000000000000000000000000000000280000000000400000800000004000000000"
          "000000000000000000000000000000000000000000000000000000000000100000100000000000000000000000"
          "00000000001400000000000000008000000000000000000000000000000000");
}

TEST_CASE("receipt with empty bloom", "[rpc][types][receipt]") {
    Logs logs{};
    Receipt r{
        TransactionType::kLegacy,
        true,
        210000,
        bloom_from_logs(logs),
        logs};
    CHECK(r.success == true);
    CHECK(r.cumulative_gas_used == 210000);
    CHECK(r.bloom == silkworm::Bloom{});
    CHECK(r.logs.empty());
}

}  // namespace silkworm::rpc
