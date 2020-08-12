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

#include <catch2/catch.hpp>
#include <silkworm/common/util.hpp>

namespace silkworm::precompiled {

TEST_CASE("Ecrecover") {
  Bytes in{from_hex(
      "18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c0000000000000000000000000000"
      "00000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9a"
      "a6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549")};
  std::optional<Bytes> out{ecrec_run(in)};
  REQUIRE(out);
  CHECK(to_hex(*out) == "000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b");

  // Unrecoverable key
  in = from_hex(
      "a8b53bdf3306a35a7103ab5504a0c9b492295564b6202b1942a84ef3001072810000000000000000000000000000"
      "00000000000000000000000000000000001b30783565316530336635336365313862373732636362303039336666"
      "37316633663533663563373562373464636233316138356161386238383932623465386211223344556677889910"
      "11121314151617181920212223242526272829303132");
  out = ecrec_run(in);
  CHECK((out && out->empty()));
}

TEST_CASE("SHA256") {
  Bytes in{from_hex(
      "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e0000000000000000000000000000"
      "00000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9"
      "ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02")};
  std::optional<Bytes> out{sha256_run(in)};
  REQUIRE(out);
  CHECK(to_hex(*out) == "811c7003375852fabd0d362e40e68607a12bdabae61a7d068fe5fdd1dbbf2a5d");
}

TEST_CASE("RIPEMD160") {
  Bytes in{from_hex(
      "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e0000000000000000000000000000"
      "00000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9"
      "ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02")};
  std::optional<Bytes> out{rip160_run(in)};
  REQUIRE(out);
  CHECK(to_hex(*out) == "0000000000000000000000009215b8d9882ff46f0dfde6684d78e831467f65e6");
}

TEST_CASE("BN_MUL") {
  Bytes in{
      from_hex("1a87b0584ce92f4593d161480614f2989035225609f08058ccfa3d0f940febe31a2f3c951f6dadcc7ee"
               "9007dff81504b0fcd6d7cf59996efdc33d92bf7f9f8f600000000000000000000000000000000000000"
               "00000000000000000000000009")};
  std::optional<Bytes> out{bn_mul_run(in)};
  REQUIRE(out);
  CHECK(to_hex(*out) ==
        "1dbad7d39dbc56379f78fac1bca147dc8e66de1b9d183c7b167351bfe0aeab742cd757d51289cd8dbd0acf9e67"
        "3ad67d0f0a89f912af47ed1be53664f5692575");
}
}  // namespace silkworm::precompiled
