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

#include "encode.hpp"

#include <sstream>
#include <string>

#include "../externals/catch2/catch.hpp"

namespace {
std::string encode_str(uint64_t n) {
  std::ostringstream s;
  silkworm::rlp::encode(s, n);
  return s.str();
}
}  // namespace

TEST_CASE("encode", "[rlp]") {
  using namespace std::string_literals;

  SECTION("uint64") {
    REQUIRE(encode_str(0) == "\x80"s);
    REQUIRE(encode_str(1) == "\x01"s);
    REQUIRE(encode_str(0x7f) == "\x7f"s);
    REQUIRE(encode_str(0x80) == "\x81\x80"s);
    REQUIRE(encode_str(0x400) == "\x82\x04\x00"s);
    REQUIRE(encode_str(0xffffb5ffffffffff) == "\x88\xFF\xFF\xB5\xFF\xFF\xFF\xFF\xFF"s);
  }
}
