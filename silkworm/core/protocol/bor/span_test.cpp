/*
   Copyright 2024 The Silkworm Authors

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

#include "span.hpp"

#include <catch2/catch.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>

namespace silkworm::protocol::bor {

// See https://docs.soliditylang.org/en/latest/abi-spec.html
TEST_CASE("GetCurrentSpan ABI") {
    static constexpr std::string_view kFunctionSignature{"getCurrentSpan()"};
    const ethash::hash256 hash{keccak256(string_view_to_byte_view(kFunctionSignature))};
    const ByteView selector{ByteView{hash.bytes}.substr(0, 4)};
    CHECK(to_hex(selector) == "af26aa96");
}

}  // namespace silkworm::protocol::bor
