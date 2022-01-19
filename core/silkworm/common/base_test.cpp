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

#include "base.hpp"

#include <catch2/catch.hpp>

#include <silkworm/rlp/encode.hpp>

#include "cast.hpp"
#include "util.hpp"

namespace silkworm {

TEST_CASE("Empty hashes") {
    const ByteView empty_string;
    const ethash::hash256 hash_of_empty_string{keccak256(empty_string)};
    CHECK(bit_cast<evmc_bytes32>(hash_of_empty_string) == kEmptyHash);

    const Bytes rlp_of_empty_list(1, rlp::kEmptyListCode);
    const ethash::hash256 hash_of_empty_list{keccak256(rlp_of_empty_list)};
    CHECK(bit_cast<evmc_bytes32>(hash_of_empty_list) == kEmptyListHash);
}

}  // namespace silkworm
