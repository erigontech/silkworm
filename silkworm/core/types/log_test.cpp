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

#include "log.hpp"

#include <catch2/catch.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

TEST_CASE("Log RLP encoding") {
    Log sample_log1{
        0xea674fdde714fd979de3edf0f56aa9716b898ec8_address,
        {},
        *from_hex("0x010043"),
    };
    std::string_view expected_rlp1{"da94ea674fdde714fd979de3edf0f56aa9716b898ec8c083010043"};

    SECTION("own encode method") {
        Bytes encoded;
        rlp::encode(encoded, sample_log1);
        CHECK(to_hex(encoded) == expected_rlp1);
    }

    SECTION("variadic struct encode") {
        Bytes encoded;
        rlp::encode(
            encoded,
            sample_log1.address,
            sample_log1.topics,
            sample_log1.data);
        CHECK(to_hex(encoded) == expected_rlp1);
    }
}

}  // namespace silkworm
