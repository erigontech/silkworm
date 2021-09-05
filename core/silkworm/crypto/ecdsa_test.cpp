/*
   Copyright 2021 The Silkworm Authors

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

#include "ecdsa.hpp"

#include <catch2/catch.hpp>

namespace silkworm::ecdsa {

TEST_CASE("EIP-155 v to y parity & chain id ") {
    CHECK(v_to_y_parity_and_chain_id(0) == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(1) == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(25) == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(26) == std::nullopt);

    CHECK(v_to_y_parity_and_chain_id(27)->odd == false);
    CHECK(v_to_y_parity_and_chain_id(27)->chain_id == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(28)->odd == true);
    CHECK(v_to_y_parity_and_chain_id(28)->chain_id == std::nullopt);

    CHECK(v_to_y_parity_and_chain_id(29) == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(30) == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(31) == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(32) == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(33) == std::nullopt);
    CHECK(v_to_y_parity_and_chain_id(34) == std::nullopt);

    CHECK(v_to_y_parity_and_chain_id(35)->odd == false);
    CHECK(v_to_y_parity_and_chain_id(35)->chain_id == 0);
    CHECK(v_to_y_parity_and_chain_id(36)->odd == true);
    CHECK(v_to_y_parity_and_chain_id(36)->chain_id == 0);

    CHECK(v_to_y_parity_and_chain_id(37)->odd == false);
    CHECK(v_to_y_parity_and_chain_id(37)->chain_id == 1);
    CHECK(v_to_y_parity_and_chain_id(38)->odd == true);
    CHECK(v_to_y_parity_and_chain_id(38)->chain_id == 1);

    CHECK(y_parity_and_chain_id_to_v(false, std::nullopt) == 27);
    CHECK(y_parity_and_chain_id_to_v(true, std::nullopt) == 28);
    CHECK(y_parity_and_chain_id_to_v(false, 1) == 37);
    CHECK(y_parity_and_chain_id_to_v(true, 1) == 38);
}

}  // namespace silkworm::ecdsa
