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

#include "request.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/trie/vector_root.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

using namespace evmc::literals;

TEST_CASE("Request RLP encoding") {
    SECTION("Deposit encode method") {
        DepositRequest deposit;
        auto bls_key = from_hex("0x54fcd2f87d667cba6cd5641c6ebe081fa0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02b").value();
        std::ranges::move(bls_key, deposit.pub_key.begin());
        deposit.withdrawal_credentials = Hash::from_hex("0xe476e5493f10afb1406727558873018d").value();
        deposit.amount = 33;
        auto bls_signature = from_hex("02b8929776df9737d2cf6487deabf0f8ecaa1f1af05df8663ee539be24c2b806030eaf5a87a64a15ae45752b94f6d8b291051dcc373ed7776dcca66eb2bffe37ead57b580c0c99fbc4830167e2d8c093cf78c6ef76993c7ad39d9b12f8a583b4").value();
        std::ranges::move(bls_signature, deposit.signature.begin());
        deposit.index = 2;

        Bytes encoded;
        encode(encoded, deposit);
        const auto expected_rlp = "80f8b6b054fcd2f87d667cba6cd5641c6ebe081fa0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02ba000000000000000000000000000000000e476e5493f10afb1406727558873018d21b86002b8929776df9737d2cf6487deabf0f8ecaa1f1af05df8663ee539be24c2b806030eaf5a87a64a15ae45752b94f6d8b291051dcc373ed7776dcca66eb2bffe37ead57b580c0c99fbc4830167e2d8c093cf78c6ef76993c7ad39d9b12f8a583b402";
        CHECK((to_hex(encoded) == expected_rlp));
    }

    SECTION("Withdrawal encode method") {
        WithdrawalRequest withdrawal;
        withdrawal.source_address = 0x00000000219ab540356cbb839cbe05303d7705fa_address;
        auto bls_key = from_hex("0xbfb0235872d6bfaf4eff049d8c35aad202654f9bc6ab16f8a9453bb575303db06acc9c360fabeeed7a7b5af7e3f41788").value();
        std::ranges::move(bls_key, withdrawal.validator_pub_key.begin());
        withdrawal.amount = 567;

        Bytes encoded;
        encode(encoded, withdrawal);
        const auto expected_rlp = "01f8499400000000219ab540356cbb839cbe05303d7705fab0bfb0235872d6bfaf4eff049d8c35aad202654f9bc6ab16f8a9453bb575303db06acc9c360fabeeed7a7b5af7e3f41788820237";
        CHECK((to_hex(encoded) == expected_rlp));
    }
}

}  // namespace silkworm
