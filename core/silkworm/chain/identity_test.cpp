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

#include "identity.hpp"

#include <catch2/catch.hpp>

namespace silkworm {

TEST_CASE("distinct_fork_numbers") {
    std::vector<BlockNum> expectedMainnetForkNumbers{
        1'150'000, 1'920'000, 2'463'000,  2'675'000,  4'370'000,  7'280'000,
        9'069'000, 9'200'000, 12'244'000, 12'965'000, 13'773'000,
    };

    CHECK(ChainIdentity::mainnet.distinct_fork_numbers() == expectedMainnetForkNumbers);

    std::vector<BlockNum> expectedGoerliForkNumbers{
        1'561'651,
        4'460'644,
        5'062'605,
    };

    CHECK(ChainIdentity::goerli.distinct_fork_numbers() == expectedGoerliForkNumbers);
}

}  // namespace silkworm
