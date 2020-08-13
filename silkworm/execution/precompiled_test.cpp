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

TEST_CASE("BN_ADD") {
  Bytes in{from_hex(
      "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000"
      "00000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000"
      "000000010000000000000000000000000000000000000000000000000000000000000002")};
  std::optional<Bytes> out{bn_add_run(in)};
  REQUIRE(out);
  CHECK(to_hex(*out) ==
        "030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd315ed738c0e0a7c92e7845f96b2"
        "ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4");
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

TEST_CASE("SNARKV") {
  // empty input
  Bytes in{};
  std::optional<Bytes> out{snarkv_run(in)};
  REQUIRE(out);
  CHECK(to_hex(*out) == "0000000000000000000000000000000000000000000000000000000000000001");

  // input size is not a multiple of 192
  in = from_hex("ab");
  out = snarkv_run(in);
  CHECK(!out);

  in = from_hex(
      "0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9"
      "bbdfec6c36c7d515536431b3a865468acbba2e89718ad33c8bed92e210e81d1853435399a271913a6520736a4729"
      "cf0d51eb01a9e2ffa2e92599b68e44de5bcf354fa2642bd4f26b259daa6f7ce3ed57aeb314a9a87b789a58af499b"
      "314e13c3d65bede56c07ea2d418d6874857b70763713178fb49a2d6cd347dc58973ff49613a20757d0fcc22079f9"
      "abd10c3baee245901b9e027bd5cfc2cb5db82d4dc9677ac795ec500ecd47deee3b5da006d6d049b811d7511c7815"
      "8de484232fc68daf8a45cf217d1c2fae693ff5871e8752d73b21198e9393920d483a7260bfb731fb5d25f1aa4933"
      "35a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed0906"
      "89d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408f"
      "e3d1e7690c43d37b4ce6cc0166fa7daa");
  out = snarkv_run(in);
  REQUIRE(out);
  CHECK(to_hex(*out) == "0000000000000000000000000000000000000000000000000000000000000001");

  in = from_hex(
      "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000"
      "000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7"
      "aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e"
      "99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b"
      "4ce6cc0166fa7daa");
  out = snarkv_run(in);
  REQUIRE(out);
  CHECK(to_hex(*out) == "0000000000000000000000000000000000000000000000000000000000000000");
}
}  // namespace silkworm::precompiled
