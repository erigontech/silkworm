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

#include "decode.hpp"

#include <boost/algorithm/hex.hpp>
#include <sstream>
#include <string_view>

// TODO(Andrew) Hunter's Catch
#include "../tests/catch.hpp"

namespace {

template <class T>
T decoded(const std::string& encoded) {
  std::istringstream stream{encoded};
  return silkworm::rlp::decode<T>(stream);
}

}  // namespace

namespace silkworm::rlp {

TEST_CASE("decode", "[rlp]") {
  using boost::algorithm::unhex;
  using Catch::Message;
  using namespace std::string_literals;

  SECTION("strings") {
    CHECK(decoded<std::string>(unhex("00"s)) == "\x00"s);
    CHECK(decoded<std::string>(unhex("8D6162636465666768696A6B6C6D"s)) == "abcdefghijklm");

    CHECK(
        decoded<std::string>("\xB8\x38Lorem ipsum dolor sit amet, consectetur adipisicing elit") ==
        "Lorem ipsum dolor sit amet, consectetur adipisicing elit");

    CHECK_THROWS_MATCHES(decoded<std::string>(unhex("C0"s)), DecodingError,
                         Message("unexpected list"));
  }

  SECTION("uint64") {
    CHECK(decoded<uint64_t>(unhex("09"s)) == 9);
    CHECK(decoded<uint64_t>(unhex("80"s)) == 0);
    CHECK(decoded<uint64_t>(unhex("820505"s)) == 0x0505);
    CHECK(decoded<uint64_t>(unhex("85CE05050505"s)) == 0xCE05050505);

    CHECK_THROWS_MATCHES(decoded<uint64_t>(unhex("C0"s)), DecodingError,
                         Message("unexpected list"));
    CHECK_THROWS_MATCHES(decoded<uint64_t>(unhex("00"s)), DecodingError,
                         Message("leading zero(s)"));
    CHECK_THROWS_MATCHES(decoded<uint64_t>(unhex("8105"s)), DecodingError,
                         Message("non-canonical single byte"));
    CHECK_THROWS_MATCHES(decoded<uint64_t>(unhex("8200F4"s)), DecodingError,
                         Message("leading zero(s)"));
    CHECK_THROWS_MATCHES(decoded<uint64_t>(unhex("B8020004"s)), DecodingError,
                         Message("non-canonical size"));
    CHECK_THROWS_MATCHES(decoded<uint64_t>(unhex("8AFFFFFFFFFFFFFFFFFF7C"s)), DecodingError,
                         Message("uint64 overflow"));
  }

  SECTION("uint256") {
    CHECK(decoded<intx::uint256>(unhex("09"s)) == 9);
    CHECK(decoded<intx::uint256>(unhex("80"s)) == 0);
    CHECK(decoded<intx::uint256>(unhex("820505"s)) == 0x0505);
    CHECK(decoded<intx::uint256>(unhex("85CE05050505"s)) == 0xCE05050505);
    CHECK(decoded<intx::uint256>(unhex("8AFFFFFFFFFFFFFFFFFF7C"s)) ==
          intx::from_string<intx::uint256>("0xFFFFFFFFFFFFFFFFFF7C"s));

    CHECK_THROWS(decoded<intx::uint256>(unhex("8BFFFFFFFFFFFFFFFFFF7C"s)));  // EOF
    CHECK_THROWS_MATCHES(decoded<intx::uint256>(unhex("C0"s)), DecodingError,
                         Message("unexpected list"));
    CHECK_THROWS_MATCHES(decoded<intx::uint256>(unhex("00"s)), DecodingError,
                         Message("leading zero(s)"));
    CHECK_THROWS_MATCHES(decoded<intx::uint256>(unhex("8105"s)), DecodingError,
                         Message("non-canonical single byte"));
    CHECK_THROWS_MATCHES(decoded<intx::uint256>(unhex("8200F4"s)), DecodingError,
                         Message("leading zero(s)"));
    CHECK_THROWS_MATCHES(decoded<intx::uint256>(unhex("B8020004"s)), DecodingError,
                         Message("non-canonical size"));
    CHECK_THROWS_MATCHES(
        decoded<intx::uint256>(
            unhex("A101000000000000000000000000000000000000008B000000000000000000000000"s)),
        DecodingError, Message("uint256 overflow"));
  }
}

}  // namespace silkworm::rlp
