// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "eip_7685_requests.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

#include "silkworm/core/protocol/param.hpp"

namespace silkworm {

using namespace evmc::literals;

TEST_CASE("EIP-7585 tests") {
    SECTION("Decode deposit receipt") {
        const auto encoded_event = from_hex(
                                       "00000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000"
                                       "000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003054fcd2f87d667cba6cd5641c6ebe081fa0f2ccddac66b88a93f2b"
                                       "96110193dcfab55b4a7ef5678b18291f5f820b1a02b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010e476e5493f10afb1406727558873018d000000000000000000000000000000000000000000000000"
                                       "0000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006002b8929776df9737d2cf6487deabf0f8ecaa1f1af05"
                                       "df8663ee539be24c2b806030eaf5a87a64a15ae45752b94f6d8b291051dcc373ed7776dcca66eb2bffe37ead57b580c0c99fbc4830167e2d8c093cf78c6ef76993c7ad39d9b12f8a583b40000000000000000000000000000000000000000000000000000000000000002014d00"
                                       "0000000000000000000000000000000000000000000000000000000000")
                                       .value();

        // Topics is a single-element vector containing hash of deposit event signature
        const std::vector logs = {Log{.address = protocol::kDepositContractAddress, .topics = {0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5_bytes32}, .data = encoded_event}};

        FlatRequests requests;
        requests.extract_deposits_from_logs(logs);
        const auto deposit_bytes = requests.preview_data_by_type(FlatRequestType::kDepositRequest);
        CHECK(deposit_bytes == from_hex("54fcd2f87d667cba6cd5641c6ebe081fa0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02be476e5493f10afb1406727558873018d2002b8929776df9737d2cf6487deabf0f8ecaa1f1af05df8663ee539be24c2b806030eaf5a87a64a15ae45752b94f6d8"
                                        "b291051dcc373ed7776dcca66eb2bffe37ead57b580c0c99fbc4830167e2d8c093cf78c6ef76993c7ad39d9b12f8a583b4014d"));
    }

    SECTION("Calculate sha256 of requests") {
        FlatRequests requests;
        requests.add_request(FlatRequestType::kDepositRequest, from_hex("54fcd2f87d667cba6cd5641c6ebe081fa0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02be476e5493f10afb1406727558873018d2002b8929776df9737d2cf6487deabf0f8ecaa1f1af05df8663ee539be24c2b8"
                                                                        "06030eaf5a87a64a15ae45752b94f6d8b291051dcc373ed7776dcca66eb2bffe37ead57b580c0c99fbc4830167e2d8c093cf78c6ef76993c7ad39d9b12f8a583b4014d")
                                                                   .value());
        requests.add_request(FlatRequestType::kWithdrawalRequest, from_hex("54fcd2f87d667cba6cd5641c6ebe081fa0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02be476e5493f10afb1406727558873018d2002b8929776df9737d2cf6487deab").value());
        requests.add_request(FlatRequestType::kConsolidationRequest, from_hex("a0f2ccddac66b88a93f2b96110193dcfab55b4a7ef5678b18291f5f820b1a02be476e5493f10afb1406727558873018d2002b89").value());

        const auto hash = requests.calculate_sha256();
        CHECK(hash == Hash{from_hex("fb11d3d094091e34794c99218a862850a4a85dc1e128ce8c85f2a2bcbcc899ef").value()});
    }

    SECTION("Calculate sha256 of empty requests") {
        FlatRequests requests;

        const auto hash = requests.calculate_sha256();
        CHECK(hash == Hash{from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").value()});
    }
}

}  // namespace silkworm
