// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "dump_account.hpp"

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/test_util/null_stream.hpp>

namespace silkworm::rpc {

static constexpr evmc::address kZeroAddress;
static constexpr evmc::bytes32 kEmptyHash;
static constexpr intx::uint256 kZeroBalance = intx::uint256{0};

using evmc::literals::operator""_address;
using evmc::literals::operator""_bytes32;

TEST_CASE("Empty DumpAccounts", "[rpc][types][dump_account]") {
    DumpAccounts da;

    SECTION("check fields") {
        CHECK(da.root == kEmptyHash);
        CHECK(da.accounts.empty());
        CHECK(da.next == kZeroAddress);
    }

    SECTION("print") {
        CHECK_NOTHROW(silkworm::test_util::null_stream() << da);
    }

    SECTION("json") {
        nlohmann::json json = da;

        CHECK(json == R"({
            "accounts": {},
            "next": "AAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        })"_json);
    }
}

TEST_CASE("Filled DumpAccounts", "[rpc][types][dump_account]") {
    DumpAccount da{
        10,
        20,
        30,
        0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32,
        0xc10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32};
    DumpAccounts das{
        0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32,
        0x79a4d418f7887dd4d5123a41b6c8c186686ae8cb_address,
        AccountsMap{
            {0x0000000000000000000000000000000000000000_address, da}}};

    SECTION("check fields") {
        CHECK(das.root == 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32);
        CHECK(das.accounts.size() == 1);
        CHECK(das.next == 0x79a4d418f7887dd4d5123a41b6c8c186686ae8cb_address);
    }

    SECTION("print") {
        CHECK_NOTHROW(silkworm::test_util::null_stream() << das);
    }

    SECTION("json") {
        nlohmann::json json = das;

        CHECK(json == R"({
            "accounts":{
                "0x0000000000000000000000000000000000000000":{
                    "balance":"10",
                    "codeHash":"0xc10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6",
                    "nonce":20,
                    "root":"0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"
                }
            },
            "next":"eaTUGPeIfdTVEjpBtsjBhmhq6Ms=",
            "root":"0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"
        })"_json);
    }
}

TEST_CASE("Filled zero-account DumpAccounts", "[rpc][types][dump_account]") {
    DumpAccounts da{
        0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32,
        0x79a4d418f7887dd4d5123a41b6c8c186686ae8cb_address};

    SECTION("check fields") {
        CHECK(da.root == 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32);
        CHECK(da.accounts.empty());
        CHECK(da.next == 0x79a4d418f7887dd4d5123a41b6c8c186686ae8cb_address);
    }

    SECTION("print") {
        CHECK_NOTHROW(silkworm::test_util::null_stream() << da);
    }

    SECTION("json") {
        nlohmann::json json = da;

        CHECK(json == R"({
            "accounts": {},
            "next": "eaTUGPeIfdTVEjpBtsjBhmhq6Ms=",
            "root": "0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"
        })"_json);
    }
}

TEST_CASE("Empty DumpAccount", "[rpc][types][dump_account]") {
    DumpAccount da;

    SECTION("check fields") {
        CHECK(da.balance == kZeroBalance);
        CHECK(da.nonce == 0);
        CHECK(da.incarnation == 0);
        CHECK(da.root == kEmptyHash);
        CHECK(da.code_hash == kEmptyHash);
        CHECK(da.code == std::nullopt);
        CHECK(da.storage == std::nullopt);
    }

    SECTION("json") {
        nlohmann::json json = da;

        CHECK(json == R"({
            "balance":"0",
            "codeHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
            "nonce":0,
            "root":"0x0000000000000000000000000000000000000000000000000000000000000000"
        })"_json);
    }
}

TEST_CASE("Filled externally-owned DumpAccount", "[rpc][types][dump_account]") {
    DumpAccount da{
        10,
        20,
        30,
        0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32,
        0xc10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32};

    SECTION("check fields") {
        CHECK(da.balance == 10);
        CHECK(da.nonce == 20);
        CHECK(da.incarnation == 30);
        CHECK(da.root == 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32);
        CHECK(da.code_hash == 0xc10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32);
        CHECK(da.code == std::nullopt);
        CHECK(da.storage == std::nullopt);
    }

    SECTION("json") {
        nlohmann::json json = da;

        CHECK(json == R"({
            "balance":"10",
            "codeHash":"0xc10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6",
            "nonce":20,
            "root":"0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"
        })"_json);
    }
}

TEST_CASE("Filled contract DumpAccount", "[rpc][types][dump_account]") {
    DumpAccount da{
        10,
        20,
        30,
        0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32,
        0xc10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32,
        silkworm::from_hex("0x0608"),
        Storage{
            {0x209f062567c161c5f71b3f57a7de277b0e95c3455050b152d785ad7524ef8ee7_bytes32,
             *silkworm::from_hex("0x0000000000000000000000000000000000000000000000000000000000000000")}}};

    SECTION("check fields") {
        CHECK(da.balance == 10);
        CHECK(da.nonce == 20);
        CHECK(da.incarnation == 30);
        CHECK(da.root == 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32);
        CHECK(da.code_hash == 0xc10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32);
        CHECK(da.code == silkworm::Bytes{0x06, 0x08});
        CHECK(da.storage == Storage{{0x209f062567c161c5f71b3f57a7de277b0e95c3455050b152d785ad7524ef8ee7_bytes32,
                                     *silkworm::from_hex("0x0000000000000000000000000000000000000000000000000000000000000000")}});
    }

    SECTION("json") {
        nlohmann::json json = da;

        CHECK(json == R"({
            "balance":"10",
            "codeHash":"0xc10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6",
            "nonce":20,
            "root":"0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6",
            "code":"0x0608",
            "storage":{
                "0x209f062567c161c5f71b3f57a7de277b0e95c3455050b152d785ad7524ef8ee7":
                "0000000000000000000000000000000000000000000000000000000000000000"
            }
        })"_json);
    }
}

}  // namespace silkworm::rpc
