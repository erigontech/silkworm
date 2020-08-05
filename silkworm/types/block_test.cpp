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

#include "block.hpp"

#include <catch2/catch.hpp>

namespace silkworm {

TEST_CASE("BlockBody RLP") {
  // https://etherscan.io/block/3
  const char* rlp_hex{
      "f90219c0f90215f90212a0d4e56740f876aef8c010b86a40d5f56745a118d090"
      "6a34e69aec8c0db1cb8fa3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b"
      "948a7413f0a142fd40d4934794c8ebccc5f5689fa8659d83713341e5ad193494"
      "48a01e6e030581fd1873b4784280859cd3b3c04aa85520f08c304cf5ee63d393"
      "5adda056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e3"
      "63b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5"
      "e363b421b9010000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "000000000000008503ff80000001821388808455ba42429a5961746573205261"
      "6e64616c6c202d2045746865724e696e6a61a0f8c94dfe61cf26dcdf8cffeda3"
      "37cf6a903d65c449d7691a022837f6e2d994598868b769c5451a7aea"};

  Bytes rlp_bytes{from_hex(rlp_hex)};
  ByteView in{rlp_bytes};
  BlockBody bb{};

  rlp::decode(in, bb);

  CHECK(bb.transactions.size() == 0);
  REQUIRE(bb.ommers.size() == 1);
  CHECK(bb.ommers[0].number == 1);
  CHECK(bb.ommers[0].beneficiary == 0xc8ebccc5f5689fa8659d83713341e5ad19349448_address);
  CHECK(bb.ommers[0].difficulty == 17'171'480'576);

  Bytes out{};
  rlp::encode(out, bb);
  CHECK(to_hex(out) == rlp_hex);
}
}  // namespace silkworm
