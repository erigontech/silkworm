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

#include "eip_7685_requests.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/trie/vector_root.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

#include "silkworm/core/protocol/param.hpp"

namespace silkworm {

using namespace evmc::literals;

TEST_CASE("Request RLP methods and signature derivation") {
    SECTION("Decode deposit receipt") {
        // const auto encoded_event = from_hex("0x00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").value();
        //
        // const std::vector logs = { Log {.address = protocol::kDepositContractAddress, .topics = {}, .data = encoded_event}};
        //
        // const auto decoded_bytes = DepositRequest::extract_deposits_from_logs(logs);
        // CHECK(decoded_bytes.empty() == false);

        // DepositRequest deposit;
        // auto bls_key = from_hex("0x54fcd2f87d667cba6cd5641c6ebe081fa0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02b").value();
        // std::ranges::copy(bls_key, deposit.pub_key.begin());
        // deposit.withdrawal_credentials = Hash::from_hex("0xe476e5493f10afb1406727558873018d").value();
        // deposit.amount = 33;
        // auto bls_signature = from_hex("0x02b8929776df9737d2cf6487deabf0f8ecaa1f1af05df8663ee539be24c2b806030eaf5a87a64a15ae45752b94f6d8b291051dcc373ed7776dcca66eb2bffe37ead57b580c0c99fbc4830167e2d8c093cf78c6ef76993c7ad39d9b12f8a583b4").value();
        // std::ranges::copy(bls_signature, deposit.signature.begin());
        // deposit.index = 2;
        //
        // CHECK(deposit.length() == 185);
        //
        // Bytes encoded;
        // encode(encoded, deposit);
        // const auto expected_rlp =
        //     "00f8b6b054fcd2f87d667cba6cd5641c6ebe081fa0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02ba000000000000000000000000000000000e476e5493f10afb1406727558873018d21b86002b8929776df9737d2cf6487deabf0f8ecaa1"
        //     "f1af05df8663ee539be24c2b806030eaf5a87a64a15ae45752b94f6d8b291051dcc373ed7776dcca66eb2bffe37ead57b580c0c99fbc4830167e2d8c093cf78c6ef76993c7ad39d9b12f8a583b402";
        // CHECK(to_hex(encoded) == expected_rlp);
        //
        // static constexpr auto kEncoder = [](Bytes& to, const Request& request) { rlp::encode(to, request); };
        //
        // const std::vector deposits = {std::move(deposit)};
        // CHECK(to_hex(trie::root_hash(deposits, kEncoder)) == "4edf1c9495ac6414f528806df9f9aff8abb337bcda2153af4b0dc5aedf89291c");
    }

    SECTION("Decode deposit receipt") {
        const auto encoded_event = from_hex("00000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003054fcd2f87d667cba6cd5641c6ebe081fa0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010e476e5493f10afb1406727558873018d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006002b8929776df9737d2cf6487deabf0f8ecaa1f1af05df8663ee539be24c2b806030eaf5a87a64a15ae45752b94f6d8b291051dcc373ed7776dcca66eb2bffe37ead57b580c0c99fbc4830167e2d8c093cf78c6ef76993c7ad39d9b12f8a583b40000000000000000000000000000000000000000000000000000000000000002014d000000000000000000000000000000000000000000000000000000000000").value();

        const std::vector logs = {Log{.address = protocol::kDepositContractAddress, .topics = {}, .data = encoded_event}};

        const auto decoded_bytes = FlatRequests::extract_deposits_from_logs(logs);
        CHECK(decoded_bytes == from_hex("54fcd2f87d667cba6cd5641c6ebe081fa0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02be476e5493f10afb1406727558873018d2002b8929776df9737d2cf6487deabf0f8ecaa1f1af05df8663ee539be24c2b806030eaf5a87a64a15ae45752b94f6d8b291051dcc373ed7776dcca66eb2bffe37ead57b580c0c99fbc4830167e2d8c093cf78c6ef76993c7ad39d9b12f8a583b4014d"));

        FlatRequests requests;
        requests.add_request(FlatRequestType::kDepositRequest, decoded_bytes);
        requests.add_request(FlatRequestType::kWithdrawalRequest, from_hex("54fcd2f87d667cba6cd5641c6ebe081fa0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02be476e5493f10afb1406727558873018d2002b8929776df9737d2cf6487deab").value());
        requests.add_request(FlatRequestType::kConsolidationRequest, from_hex("a0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02be476e5493f10afb1406727558873018d2002b89").value());

        const auto hash = requests.calculate_sha256();
        CHECK(hash == Hash{from_hex("fb11d3d094091e34794c99218a862850a4a85dc1e128ce8c85f2a2bcbcc899ef").value()});
    }

    SECTION("DepositRequest rlp and signature") {
        // DepositRequest deposit;
        // auto bls_key = from_hex("0x54fcd2f87d667cba6cd5641c6ebe081fa0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02b").value();
        // std::ranges::copy(bls_key, deposit.pub_key.begin());
        // deposit.withdrawal_credentials = Hash::from_hex("0xe476e5493f10afb1406727558873018d").value();
        // deposit.amount = 33;
        // auto bls_signature = from_hex("0x02b8929776df9737d2cf6487deabf0f8ecaa1f1af05df8663ee539be24c2b806030eaf5a87a64a15ae45752b94f6d8b291051dcc373ed7776dcca66eb2bffe37ead57b580c0c99fbc4830167e2d8c093cf78c6ef76993c7ad39d9b12f8a583b4").value();
        // std::ranges::copy(bls_signature, deposit.signature.begin());
        // deposit.index = 2;
        //
        // CHECK(deposit.length() == 185);
        //
        // Bytes encoded;
        // encode(encoded, deposit);
        // const auto expected_rlp =
        //     "00f8b6b054fcd2f87d667cba6cd5641c6ebe081fa0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02ba000000000000000000000000000000000e476e5493f10afb1406727558873018d21b86002b8929776df9737d2cf6487deabf0f8ecaa1"
        //     "f1af05df8663ee539be24c2b806030eaf5a87a64a15ae45752b94f6d8b291051dcc373ed7776dcca66eb2bffe37ead57b580c0c99fbc4830167e2d8c093cf78c6ef76993c7ad39d9b12f8a583b402";
        // CHECK(to_hex(encoded) == expected_rlp);
        //
        // static constexpr auto kEncoder = [](Bytes& to, const Request& request) { rlp::encode(to, request); };
        //
        // const std::vector deposits = {std::move(deposit)};
        // CHECK(to_hex(trie::root_hash(deposits, kEncoder)) == "4edf1c9495ac6414f528806df9f9aff8abb337bcda2153af4b0dc5aedf89291c");
    }

    SECTION("WithdrawalRequest rlp and signature") {
        // WithdrawalRequest withdrawal;
        // withdrawal.source_address = 0x00000000219ab540356cbb839cbe05303d7705fa_address;
        // auto bls_key = from_hex("0xbfb0235872d6bfaf4eff049d8c35aad202654f9bc6ab16f8a9453bb575303db06acc9c360fabeeed7a7b5af7e3f41788").value();
        // std::ranges::move(bls_key, withdrawal.validator_pub_key.begin());
        // withdrawal.amount = 567;
        //
        // CHECK(withdrawal.length() == 76);
        //
        // Bytes encoded;
        // encode(encoded, withdrawal);
        // const auto expected_rlp = "01f8499400000000219ab540356cbb839cbe05303d7705fab0bfb0235872d6bfaf4eff049d8c35aad202654f9bc6ab16f8a9453bb575303db06acc9c360fabeeed7a7b5af7e3f41788820237";
        // CHECK((to_hex(encoded) == expected_rlp));
        //
        // static constexpr auto kEncoder = [](Bytes& to, const Request& request) { rlp::encode(to, request); };
        // const std::vector withdrawals = {std::move(withdrawal)};
        // CHECK(to_hex(trie::root_hash(withdrawals, kEncoder)) == "d45823f549b11af3c38e4ae7f11779a2ecc7271dc93bafa5456a787eb183bf96");
    }

    SECTION("ConsolidationRequest rlp and signature") {
        // ConsolidationRequest consolidation;
        // consolidation.source_address = 0xe476e5493f10afb1406727558873018d_address;
        // auto bls_key = from_hex("0xbfb0235872d6bfaf4eff049d8c35aad202654f9bc6ab16f8a9453bb575303db06acc9c360fabeeed7a7b5af7e3f41788").value();
        // std::ranges::move(bls_key, consolidation.source_pub_key.begin());
        //
        // bls_key = from_hex("0x54fcd2f87d667cba6cd5641c6ebe081fa0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02b").value();
        // std::ranges::move(bls_key, consolidation.target_pub_key.begin());
        //
        // CHECK(consolidation.length() == 122);
        //
        // Bytes encoded;
        // encode(encoded, consolidation);
        // const auto expected_rlp = "02f8779400000000e476e5493f10afb1406727558873018db0bfb0235872d6bfaf4eff049d8c35aad202654f9bc6ab16f8a9453bb575303db06acc9c360fabeeed7a7b5af7e3f41788b054fcd2f87d667cba6cd5641c6ebe081fa0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02b";
        // CHECK((to_hex(encoded) == expected_rlp));
        //
        // static constexpr auto kEncoder = [](Bytes& to, const Request& request) { rlp::encode(to, request); };
        // const std::vector consolidations = {std::move(consolidation)};
        // CHECK(to_hex(trie::root_hash(consolidations, kEncoder)) == "fadf31af3c7783255db6cc15397399b48aa0e86ed3596eedaafc74b2615524d0");
    }

    SECTION("Bulk requests decoding") {
        // std::vector<RequestPtr> requests;
        //
        // auto input = Bytes{from_hex("f8b900f8b6b054fcd2f87d667cba6cd5641c6ebe081fa0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02ba000000000000000000000000000000000e476e5493f10afb1406727558873018d21b86002b8929776df9737d2cf6487deabf0f8ecaa1f1af05df8663ee539be24c2b806030eaf5a87a64a15ae45752b94f6d8b291051dcc373ed7776dcca66eb2bffe37ead57b580c0c99fbc4830167e2d8c093cf78c6ef76993c7ad39d9b12f8a583b402").value()};
        // auto from = ByteView{input};
        // const auto result = decode(from, requests, rlp::Leftover::kAllow);
        //
        // CHECK(result.has_value());
        // CHECK(requests.size() == 1);
        //
        // const auto& deposit = dynamic_cast<DepositRequest&>(*requests[0].get());
        //
        // CHECK(deposit.amount == 33);
        // CHECK(deposit.index == 2);
        // CHECK(ByteView{deposit.pub_key} == ByteView{from_hex("0x54fcd2f87d667cba6cd5641c6ebe081fa0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02b").value()});
        // CHECK(ByteView{deposit.signature} == ByteView{from_hex("0x02b8929776df9737d2cf6487deabf0f8ecaa1f1af05df8663ee539be24c2b806030eaf5a87a64a15ae45752b94f6d8b291051dcc373ed7776dcca66eb2bffe37ead57b580c0c99fbc4830167e2d8c093cf78c6ef76993c7ad39d9b12f8a583b4").value()});
        // CHECK(deposit.withdrawal_credentials == Hash::from_hex("0xe476e5493f10afb1406727558873018d").value());
    }
}

}  // namespace silkworm
