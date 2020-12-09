/*
   Copyright 2020 The Silkworm Authors

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

#include <catch2/catch.hpp>

namespace silkworm {

using namespace evmc::literals;

TEST_CASE("Create address") {
    CHECK(create_address(0xfbe0afcd7658ba86be41922059dd879c192d4c73_address, 0) ==
          0xc669eaad75042be84daaf9b461b0e868b9ac1871_address);
}
}  // namespace silkworm
