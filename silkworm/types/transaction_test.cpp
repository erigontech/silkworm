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

#include "transaction.hpp"

#include <catch2/catch.hpp>
#include <silkworm/common/util.hpp>
#include <sstream>

namespace silkworm {

TEST_CASE("Transaction RLP") {
  Transaction txn{
      12,                                                  // nonce
      20000000000,                                         // .gas_price
      21000,                                               // .gas_limit
      0x727fc6a68321b754475c668a6abfb6e9e71c169a_address,  // to
      10 * kEther,                                         // .value
      from_hex("a9059cbb000000000213ed0f886efd100b67c7e4ec0a85a7d20dc9716000000000000000000"
               "00015af1d78b58c4000"),  // data
      intx::from_string<intx::uint256>(
          "0x5a896eab396e6ff9d78e157224bc66aa4593114b1f87dadf73d035fa6c3930fc"),  // v
      intx::from_string<intx::uint256>(
          "0xbe67e0a07db67da8d446f76add590e54b6e92cb6b8f9835aeb67540579a27717"),  // r
      intx::from_string<intx::uint256>(
          "0x2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7bd718"),  // s
  };

  std::stringstream stream;
  rlp::encode(stream, txn);

  Transaction decoded;
  rlp::decode<Transaction>(stream, decoded);
  CHECK(decoded == txn);
}
}  // namespace silkworm
