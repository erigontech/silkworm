// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "test_util.hpp"

#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/core/types/log.hpp>

namespace silkworm::test {

std::vector<Transaction> sample_transactions() {
    std::vector<Transaction> transactions;
    transactions.resize(2);

    transactions[0].nonce = 172339;
    transactions[0].max_priority_fee_per_gas = 50 * kGiga;
    transactions[0].max_fee_per_gas = 50 * kGiga;
    transactions[0].gas_limit = 90'000;
    transactions[0].to = 0xe5ef458d37212a06e3f59d40c454e76150ae7c32_address;
    transactions[0].value = 1'027'501'080 * kGiga;
    transactions[0].data = {};
    static_cast<void>(transactions[0].set_v(27));
    transactions[0].r =
        intx::from_string<intx::uint256>("0x48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353");
    transactions[0].s =
        intx::from_string<intx::uint256>("0x1fffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804");

    transactions[1].type = TransactionType::kDynamicFee;
    transactions[1].nonce = 1;
    transactions[1].max_priority_fee_per_gas = 5 * kGiga;
    transactions[1].max_fee_per_gas = 30 * kGiga;
    transactions[1].gas_limit = 1'000'000;
    transactions[1].to = {};
    transactions[1].value = 0;
    transactions[1].data = *from_hex("602a6000556101c960015560068060166000396000f3600035600055");
    static_cast<void>(transactions[1].set_v(37));
    transactions[1].r =
        intx::from_string<intx::uint256>("0x52f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb");
    transactions[1].s =
        intx::from_string<intx::uint256>("0x52f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb");

    return transactions;
}

std::vector<Receipt> sample_receipts() {
    std::vector<Receipt> receipts{};
    receipts.resize(2);

    receipts[0].type = TransactionType::kLegacy;
    receipts[0].success = false;
    receipts[0].cumulative_gas_used = 0x32f05d;
    receipts[0].logs = {
        Log{
            0xea674fdde714fd979de3edf0f56aa9716b898ec8_address,
            {},
            *from_hex("0x010043"),
        },
        Log{
            0x44fd3ab8381cc3d14afa7c4af7fd13cdc65026e1_address,
            {to_bytes32(*from_hex("dead")), to_bytes32(*from_hex("abba"))},
            *from_hex("0xaabbff780043"),
        },
    };

    receipts[1].type = TransactionType::kDynamicFee;
    receipts[1].success = true;
    receipts[1].cumulative_gas_used = 0xbeadd0;
    receipts[1].logs = {};

    return receipts;
}

}  // namespace silkworm::test
