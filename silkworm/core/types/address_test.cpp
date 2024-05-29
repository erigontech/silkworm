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

#include "address.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

using namespace evmc::literals;

TEST_CASE("Create address") {
    CHECK(create_address(0xfbe0afcd7658ba86be41922059dd879c192d4c73_address, 0) ==
          0xc669eaad75042be84daaf9b461b0e868b9ac1871_address);
}

TEST_CASE("Create2 address") {
    auto init_code_hash{0x574cde0b89679c30a3c3b5c32c3dc25db6e980e912e399d5bbc887cdf3c85b1b_bytes32};
    auto salt{0x000000000000000000000000000000000000000000000000000000000004bc00_bytes32};

    CHECK(create2_address(0xfbe0afcd7658ba86be41922059dd879c192d4c73_address, salt, init_code_hash.bytes) ==
          0xd6eeefd603dcbedc00bebf93b4cacdfc8d8f241f_address);
}
}  // namespace silkworm
