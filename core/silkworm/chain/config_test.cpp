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

#include "config.hpp"

#include <catch2/catch.hpp>

namespace silkworm {

TEST_CASE("Config lookup") {
    CHECK(lookup_chain_config(0) == nullptr);
    CHECK(lookup_chain_config(1) == &kMainnetConfig);
    CHECK(lookup_chain_config(3) == &kRopstenConfig);
    CHECK(lookup_chain_config(4) == &kRinkebyConfig);
    CHECK(lookup_chain_config(5) == &kGoerliConfig);
    CHECK(lookup_chain_config(61) == &kClassicMainnetConfig);
    CHECK(lookup_chain_config(12345) == nullptr);
}

}  // namespace silkworm
