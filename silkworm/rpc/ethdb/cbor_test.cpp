// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "cbor.hpp"

#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/rpc/types/log.hpp>
#include <silkworm/rpc/types/receipt.hpp>

namespace {
#ifdef _WIN32
const char* kInvalidArgumentMessage = "invalid argument";
#else
const char* kInvalidArgumentMessage = "Invalid argument";
#endif
}  // namespace

namespace silkworm::rpc {

using Catch::Matchers::Message;
using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;
using std::string_literals::operator""s;

TEST_CASE("decode logs from empty bytes", "[rpc][ethdb][cbor]") {
    Logs logs{};
    CHECK_NOTHROW(cbor_decode(*silkworm::from_hex(""), logs));
    CHECK(logs.empty());
}

TEST_CASE("decode logs from empty array", "[rpc][ethdb][cbor]") {
    Logs logs{};
    CHECK_NOTHROW(cbor_decode(*silkworm::from_hex("80"), logs));
    CHECK(logs.empty());
}

TEST_CASE("decode logs from CBOR 1", "[rpc][ethdb][cbor]") {
    Logs logs{};
    CHECK_NOTHROW(cbor_decode(*silkworm::from_hex("818354000000000000000000000000000000000000000080f6"), logs));
    CHECK(logs.size() == 1);
    CHECK(logs[0].address == 0x0000000000000000000000000000000000000000_address);
    CHECK(logs[0].topics.empty());
    CHECK(logs[0].data.empty());
}

TEST_CASE("decode logs from CBOR 2", "[rpc][ethdb][cbor]") {
    Logs logs{};
    CHECK_NOTHROW(cbor_decode(*silkworm::from_hex(
                                  "82"
                                  "83540715a7794a1dc8e42615f059dd6e406a6594651a80f6"
                                  "8354007fb8417eb9ad4d958b050fc3720d5b46a2c053805000110011001100110011001100110011"),
                              logs));
    CHECK(logs.size() == 2);
    CHECK(logs[0].address == 0x0715a7794a1dc8e42615f059dd6e406a6594651a_address);
    CHECK(logs[0].topics.empty());
    CHECK(logs[0].data.empty());
    CHECK(logs[1].address == 0x007fb8417eb9ad4d958b050fc3720d5b46a2c053_address);
    CHECK(logs[1].topics.empty());
    CHECK(logs[1].data == *silkworm::from_hex("00110011001100110011001100110011"));
}

TEST_CASE("decode logs from CBOR 3", "[rpc][ethdb][cbor]") {
    Logs logs{};
    auto bytes = *silkworm::from_hex("818354ea674fdde714fd979de3edf0f56aa9716b898ec88043010043");
    CHECK_NOTHROW(cbor_decode(bytes, logs));
    CHECK(logs.size() == 1);
    CHECK(logs[0].address == 0xea674fdde714fd979de3edf0f56aa9716b898ec8_address);
    CHECK(logs[0].topics.empty());
    CHECK(silkworm::to_hex(logs[0].data) == "010043");
}

TEST_CASE("decode logs from CBOR 4", "[rpc][ethdb][cbor]") {
    Logs logs{};
    auto bytes = *silkworm::from_hex(
        "81835456c0369e002852c2570ca0cc3442e26df98e01a2835820ddf252ad1be2c89b69c2b068fc37"
        "8daa952ba7f163c4a11628f55a4df523b3ef5820000000000000000000000000a2e1ffe3aa9cbcde"
        "1955b04d22e2cc092c3738785820000000000000000000000000520d849db6e4bf7e0c58a45fc513"
        "a6d633baf77e5820000000000000000000000000000000000000000000084595161401484a000000");
    CHECK_NOTHROW(cbor_decode(bytes, logs));
    CHECK(logs.size() == 1);
    CHECK(logs[0].address == 0x56c0369e002852c2570ca0cc3442e26df98e01a2_address);
    CHECK(logs[0].topics.size() == 3);
    CHECK(logs[0].topics == std::vector<evmc::bytes32>{
                                0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef_bytes32,
                                0x000000000000000000000000a2e1ffe3aa9cbcde1955b04d22e2cc092c373878_bytes32,
                                0x000000000000000000000000520d849db6e4bf7e0c58a45fc513a6d633baf77e_bytes32,
                            });
    CHECK(silkworm::to_hex(logs[0].data) == "000000000000000000000000000000000000000000084595161401484a000000");
}

TEST_CASE("decode logs from incorrect bytes", "[rpc][ethdb][cbor]") {
    Logs logs{};
    const Bytes b1 = *silkworm::from_hex("81");
    CHECK(!cbor_decode(b1, logs));
    const Bytes b2 = *silkworm::from_hex("83808040");
    CHECK_THROWS_MATCHES(cbor_decode(b2, logs), std::invalid_argument, Message("Log CBOR: unexpected format(on_array wrong number of fields)"));
}

TEST_CASE("decode receipts from empty bytes", "[rpc][ethdb][cbor]") {
    Receipts receipts{};
    CHECK_NOTHROW(cbor_decode(*silkworm::from_hex(""), receipts));
    CHECK(receipts.empty());
}

TEST_CASE("decode receipts from empty array", "[rpc][ethdb][cbor]") {
    Receipts receipts{};
    CHECK_NOTHROW(cbor_decode(*silkworm::from_hex("80"), receipts));
    CHECK(receipts.empty());
}

TEST_CASE("decode receipts from CBOR 1", "[rpc][ethdb][cbor]") {
    Receipts receipts{};
    CHECK_NOTHROW(cbor_decode(*silkworm::from_hex("818400f60101"), receipts));
    CHECK(receipts.size() == 1);
    CHECK(receipts[0].type == TransactionType::kLegacy);
    CHECK(receipts[0].success == 1);
    CHECK(receipts[0].cumulative_gas_used == 1);
}

TEST_CASE("decode receipts from CBOR 2", "[rpc][ethdb][cbor]") {
    Receipts receipts{};
    CHECK_NOTHROW(cbor_decode(*silkworm::from_hex(
                                  "82"
                                  "8400f60101"
                                  "8400f60101"),
                              receipts));
    CHECK(receipts.size() == 2);
    CHECK(receipts[0].type == TransactionType::kLegacy);
    CHECK(receipts[0].success == 1);
    CHECK(receipts[0].cumulative_gas_used == 1);
    CHECK(receipts[1].type == TransactionType::kLegacy);
    CHECK(receipts[1].success == 1);
    CHECK(receipts[1].cumulative_gas_used == 1);
}

TEST_CASE("decode receipts from CBOR 3", "[rpc][ethdb][cbor]") {
    Receipts receipts{};
    auto bytes = *silkworm::from_hex("838400f601196d398400f6011a00371b0b8400f6011a003947f4");
    CHECK_NOTHROW(cbor_decode(bytes, receipts));
    CHECK(receipts.size() == 3);
    CHECK(receipts[0].success == true);
    CHECK(receipts[0].cumulative_gas_used == 0x6d39);
    CHECK(receipts[1].success == true);
    CHECK(receipts[1].cumulative_gas_used == 0x371b0b);
    CHECK(receipts[2].success == true);
    CHECK(receipts[2].cumulative_gas_used == 0x3947f4);
}

TEST_CASE("decode receipts from incorrect bytes", "[rpc][ethdb][cbor]") {
    Receipts receipts{};
    const Bytes b1 = *silkworm::from_hex("81");
    CHECK_THROWS(cbor_decode(b1, receipts));
    const Bytes b2 = *silkworm::from_hex("83808040");
    CHECK_THROWS_MATCHES(cbor_decode(b2, receipts), std::system_error, Message("Receipt CBOR: missing entries: "s + kInvalidArgumentMessage));
}

}  // namespace silkworm::rpc
