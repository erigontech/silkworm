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
    CHECK(!v_to_y_parity_and_chain_id(27).odd);
    CHECK(v_to_y_parity_and_chain_id(28).odd);
    CHECK(!v_to_y_parity_and_chain_id(27).chain_id);
    CHECK(!v_to_y_parity_and_chain_id(28).chain_id);

    CHECK(!v_to_y_parity_and_chain_id(37).odd);
    CHECK(v_to_y_parity_and_chain_id(38).odd);
    CHECK(v_to_y_parity_and_chain_id(37).chain_id == 1);
    CHECK(v_to_y_parity_and_chain_id(38).chain_id == 1);

    CHECK(y_parity_and_chain_id_to_v(false, std::nullopt) == 27);
    CHECK(y_parity_and_chain_id_to_v(true, std::nullopt) == 28);
    CHECK(y_parity_and_chain_id_to_v(false, 1) == 37);
    CHECK(y_parity_and_chain_id_to_v(true, 1) == 38);
}

}  // namespace silkworm::ecdsa
