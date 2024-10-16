/*
   Copyright 2023 The Silkworm Authors

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

#include "validation.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/test_util.hpp>
#include <silkworm/core/state/in_memory_state.hpp>

namespace silkworm::protocol {

TEST_CASE("Validate transaction types") {
    const std::optional<intx::uint256> base_fee_per_gas{std::nullopt};
    const std::optional<intx::uint256> blob_gas_price{std::nullopt};

    Transaction txn;
    txn.type = TransactionType::kLegacy;
    CHECK(pre_validate_transaction(txn, EVMC_ISTANBUL, 1, base_fee_per_gas, blob_gas_price) !=
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_BERLIN, 1, base_fee_per_gas, blob_gas_price) !=
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, 1, base_fee_per_gas, blob_gas_price) !=
          ValidationResult::kUnsupportedTransactionType);

    txn.type = static_cast<TransactionType>(0x03);  // unsupported transaction type
    CHECK(pre_validate_transaction(txn, EVMC_ISTANBUL, 1, base_fee_per_gas, blob_gas_price) ==
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_BERLIN, 1, base_fee_per_gas, blob_gas_price) ==
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, 1, base_fee_per_gas, blob_gas_price) ==
          ValidationResult::kUnsupportedTransactionType);

    txn.type = TransactionType::kAccessList;
    CHECK(pre_validate_transaction(txn, EVMC_ISTANBUL, 1, base_fee_per_gas, blob_gas_price) ==
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_BERLIN, 1, base_fee_per_gas, blob_gas_price) !=
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, 1, base_fee_per_gas, blob_gas_price) !=
          ValidationResult::kUnsupportedTransactionType);

    txn.type = TransactionType::kDynamicFee;
    CHECK(pre_validate_transaction(txn, EVMC_ISTANBUL, 1, base_fee_per_gas, blob_gas_price) ==
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_BERLIN, 1, base_fee_per_gas, blob_gas_price) ==
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, 1, base_fee_per_gas, blob_gas_price) !=
          ValidationResult::kUnsupportedTransactionType);
}

TEST_CASE("Validate max_fee_per_gas") {
    const std::optional<intx::uint256> base_fee_per_gas{1'000'000'000};
    const std::optional<intx::uint256> blob_gas_price{std::nullopt};

    Transaction txn;
    txn.type = TransactionType::kDynamicFee;

    txn.max_priority_fee_per_gas = 500'000'000;
    txn.max_fee_per_gas = 700'000'000;
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, 1, base_fee_per_gas, blob_gas_price) ==
          ValidationResult::kMaxFeeLessThanBase);

    txn.max_priority_fee_per_gas = 3'000'000'000;
    txn.max_fee_per_gas = 2'000'000'000;
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, 1, base_fee_per_gas, blob_gas_price) ==
          ValidationResult::kMaxPriorityFeeGreaterThanMax);

    txn.max_priority_fee_per_gas = 2'000'000'000;
    txn.max_fee_per_gas = 2'000'000'000;
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, 1, base_fee_per_gas, blob_gas_price) !=
          ValidationResult::kMaxPriorityFeeGreaterThanMax);

    txn.max_priority_fee_per_gas = 1'000'000'000;
    txn.max_fee_per_gas = 2'000'000'000;
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, 1, base_fee_per_gas, blob_gas_price) !=
          ValidationResult::kMaxPriorityFeeGreaterThanMax);
}

TEST_CASE("Validate withdrawals_root") {
    BlockBody body;

    SECTION("no withdrawals") {
        CHECK(compute_withdrawals_root(body) == std::nullopt);
    }
    SECTION("empty withdrawals") {
        body.withdrawals = std::vector<Withdrawal>{};
        CHECK(compute_withdrawals_root(body) == kEmptyRoot);
    }
    SECTION("non-empty withdrawals") {  // mainnet block 17'034'871
        body.withdrawals = std::vector<Withdrawal>{
            {.index = 0, .validator_index = 24862, .address = 0x6193f68d97921f4765d72A3E6964fc990c59E0e5_address, .amount = 4451500756},
            {.index = 1, .validator_index = 26591, .address = 0x9d213dE20AFd12c56075137bCb68d0d386122A0c_address, .amount = 4547643423},
            {.index = 2, .validator_index = 27573, .address = 0xcfc7E96Be27d836b034b37132052549611341108_address, .amount = 4440880509},
        };
        CHECK(compute_withdrawals_root(body) == 0xc32381c919dad80afe8fe0df79460418e350725a63f67c55b27ee168ef464e5d_bytes32);
    }
}

TEST_CASE("EIP-3607: Reject transactions from senders with deployed code") {
    const evmc::address sender{0x71562b71999873DB5b286dF957af199Ec94617F7_address};

    Transaction txn{test::sample_transactions()[0]};
    txn.nonce = 0;
    txn.set_sender(sender);

    InMemoryState state;
    IntraBlockState ibs{state};

    ibs.add_to_balance(sender, 10 * kEther);
    ibs.set_code(sender, *from_hex("B0B0FACE"));

    CHECK(validate_transaction(txn, ibs, UINT64_MAX) == ValidationResult::kSenderNoEOA);
}

TEST_CASE("EIP-7702: Reject transactions with zero destination address") {
    const evmc::address sender{0x71562b71999873DB5b286dF957af199Ec94617F7_address};

    Transaction txn{test::sample_transactions()[0]};
    txn.nonce = 0;
    txn.set_sender(sender);

    txn.authorizations.emplace_back(Authorization{});

    InMemoryState state;
    IntraBlockState ibs{state};

    ibs.add_to_balance(sender, 10 * kEther);
    ibs.set_code(sender, *from_hex("B0B0FACE"));

    CHECK(validate_transaction(txn, ibs, UINT64_MAX) == ValidationResult::kSenderNoEOA);
}

}  // namespace silkworm::protocol
