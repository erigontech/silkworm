/*
   Copyright 2020-2021 The Silkworm Authors

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

namespace silkworm {

TEST_CASE("Transaction RLP") {
    Transaction txn{
        12,                                                  // nonce
        20000000000,                                         // gas_price
        21000,                                               // gas_limit
        0x727fc6a68321b754475c668a6abfb6e9e71c169a_address,  // to
        10 * kEther,                                         // value
        *from_hex("a9059cbb000000000213ed0f886efd100b67c7e4ec0a85a7d20dc9716000000000000000000"
                  "00015af1d78b58c4000"),                                                                        // data
        intx::from_string<intx::uint256>("0x5a896eab396e6ff9d78e157224bc66aa4593114b1f87dadf73d035fa6c3930fc"),  // v
        intx::from_string<intx::uint256>("0xbe67e0a07db67da8d446f76add590e54b6e92cb6b8f9835aeb67540579a27717"),  // r
        intx::from_string<intx::uint256>("0x2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7bd718"),  // s
    };

    Bytes encoded{};
    rlp::encode(encoded, txn);

    Transaction decoded;
    ByteView view{encoded};
    REQUIRE(rlp::decode<Transaction>(view, decoded) == rlp::DecodingResult::kOk);
    CHECK(decoded == txn);
}

TEST_CASE("Recover sender 1") {
    // https://etherscan.io/tx/0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060
    // Block 46147
    Transaction txn{
        0,                                                   // nonce
        50'000 * kGiga,                                      // gas_price
        21'000,                                              // gas_limit
        0x5df9b87991262f6ba471f09758cde1c0fc1de734_address,  // to
        31337,                                               // value
        {},                                                  // data
        28,                                                  // v
        intx::from_string<intx::uint256>("0x88ff6cf0fefd94db46111149ae4bfc179e9b94721fffd821d38d16464b3f71d0"),  // r
        intx::from_string<intx::uint256>("0x45e0aff800961cfce805daef7016b9b675c137a6a41a548f7b60a3484c06a33a"),  // s
    };

    txn.recover_sender(/*homestead=*/false, {});
    CHECK(txn.from == 0xa1e4380a3b1f749673e270229993ee55f35663b4_address);
}

TEST_CASE("Recover sender 2") {
    // https://etherscan.io/tx/0xe17d4d0c4596ea7d5166ad5da600a6fdc49e26e0680135a2f7300eedfd0d8314
    // Block 46214
    Transaction txn{
        1,                                                   // nonce
        50'000 * kGiga,                                      // gas_price
        21'750,                                              // gas_limit
        0xc9d4035f4a9226d50f79b73aafb5d874a1b6537e_address,  // to
        31337,                                               // value
        *from_hex("0x74796d3474406469676978"),               // data
        28,                                                  // v
        intx::from_string<intx::uint256>("0x1c48defe76d367bb92b4fc0628aca42a4d8037062865635d955673e57eddfbfa"),  // r
        intx::from_string<intx::uint256>("0x65f766849f97b15f01d0877636fbed0fa4e39f8834896c0354f56ac44dcb50a6"),  // s
    };

    txn.recover_sender(/*homestead=*/false, {});
    CHECK(txn.from == 0xa1e4380a3b1f749673e270229993ee55f35663b4_address);
}

}  // namespace silkworm
