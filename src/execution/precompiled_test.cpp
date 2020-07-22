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

#include "precompiled.hpp"

#include <boost/algorithm/hex.hpp>
#include <catch2/catch.hpp>

#include "common/util.hpp"

namespace silkworm::precompiled {

TEST_CASE("Ecrecover") {
  using namespace std::string_literals;
  using boost::algorithm::unhex;

  std::string in{unhex(
      "18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c0000000000000000000000000000"
      "00000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9a"
      "a6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549"s)};
  std::optional<std::string> out{ecrec_run(in)};
  REQUIRE(out);
  CHECK(to_hex(*out) == "000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b");

  // Unrecoverable key
  in = unhex(
      "a8b53bdf3306a35a7103ab5504a0c9b492295564b6202b1942a84ef3001072810000000000000000000000000000"
      "00000000000000000000000000000000001b30783565316530336635336365313862373732636362303039336666"
      "37316633663533663563373562373464636233316138356161386238383932623465386211223344556677889910"
      "11121314151617181920212223242526272829303132"s);
  out = ecrec_run(in);
  CHECK((out && out->empty()));
}
}  // namespace silkworm::precompiled
