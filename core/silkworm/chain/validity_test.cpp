/*
   Copyright 2021 The Silkworm Authors

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

#include "validity.hpp"

#include <catch2/catch.hpp>

namespace silkworm {

static const ChainConfig kTestConfig{
    1,  // chain_id
    SealEngineType::kNoProof,
    {
        EVMC_HOMESTEAD,
        EVMC_TANGERINE_WHISTLE,
        EVMC_SPURIOUS_DRAGON,
        EVMC_BYZANTIUM,
        EVMC_CONSTANTINOPLE,
        EVMC_PETERSBURG,
        EVMC_ISTANBUL,
        EVMC_BERLIN,
        EVMC_LONDON,
    },
};

TEST_CASE("Validate transaction types") {
    const std::optional<intx::uint256> base_fee_per_gas{std::nullopt};

    Transaction txn;
    txn.type = Transaction::Type::kLegacy;
    CHECK(pre_validate_transaction(txn, EVMC_ISTANBUL, kTestConfig, base_fee_per_gas) !=
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_BERLIN, kTestConfig, base_fee_per_gas) !=
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, kTestConfig, base_fee_per_gas) !=
          ValidationResult::kUnsupportedTransactionType);

    txn.type = static_cast<Transaction::Type>(0x03);  // unsupported transaction type
    CHECK(pre_validate_transaction(txn, EVMC_ISTANBUL, kTestConfig, base_fee_per_gas) ==
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_BERLIN, kTestConfig, base_fee_per_gas) ==
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, kTestConfig, base_fee_per_gas) ==
          ValidationResult::kUnsupportedTransactionType);

    txn.type = Transaction::Type::kEip2930;
    CHECK(pre_validate_transaction(txn, EVMC_ISTANBUL, kTestConfig, base_fee_per_gas) ==
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_BERLIN, kTestConfig, base_fee_per_gas) !=
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, kTestConfig, base_fee_per_gas) !=
          ValidationResult::kUnsupportedTransactionType);

    txn.type = Transaction::Type::kEip1559;
    CHECK(pre_validate_transaction(txn, EVMC_ISTANBUL, kTestConfig, base_fee_per_gas) ==
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_BERLIN, kTestConfig, base_fee_per_gas) ==
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, kTestConfig, base_fee_per_gas) !=
          ValidationResult::kUnsupportedTransactionType);
}

TEST_CASE("Validate max_fee_per_gas") {
    const std::optional<intx::uint256> base_fee_per_gas{1'000'000'000};

    Transaction txn;
    txn.type = Transaction::Type::kEip1559;

    txn.max_priority_fee_per_gas = 500'000'000;
    txn.max_fee_per_gas = 700'000'000;
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, kTestConfig, base_fee_per_gas) ==
          ValidationResult::kMaxFeeLessThanBase);

    txn.max_priority_fee_per_gas = 3'000'000'000;
    txn.max_fee_per_gas = 2'000'000'000;
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, kTestConfig, base_fee_per_gas) ==
          ValidationResult::kMaxPriorityFeeGreaterThanMax);

    txn.max_priority_fee_per_gas = 2'000'000'000;
    txn.max_fee_per_gas = 2'000'000'000;
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, kTestConfig, base_fee_per_gas) !=
          ValidationResult::kMaxPriorityFeeGreaterThanMax);

    txn.max_priority_fee_per_gas = 1'000'000'000;
    txn.max_fee_per_gas = 2'000'000'000;
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, kTestConfig, base_fee_per_gas) !=
          ValidationResult::kMaxPriorityFeeGreaterThanMax);
}

}  // namespace silkworm
