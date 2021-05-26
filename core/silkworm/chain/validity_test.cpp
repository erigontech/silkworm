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

TEST_CASE("Validate transaction types") {
    const std::optional<intx::uint256> base_fee_per_gas{std::nullopt};

    const ChainConfig config{
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

    Transaction txn;
    txn.type = std::nullopt;  // legacy
    CHECK(pre_validate_transaction(txn, EVMC_ISTANBUL, config, base_fee_per_gas) !=
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_BERLIN, config, base_fee_per_gas) !=
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, config, base_fee_per_gas) !=
          ValidationResult::kUnsupportedTransactionType);

    txn.type = 0;  // unsupported transaction type
    CHECK(pre_validate_transaction(txn, EVMC_ISTANBUL, config, base_fee_per_gas) ==
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_BERLIN, config, base_fee_per_gas) ==
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, config, base_fee_per_gas) ==
          ValidationResult::kUnsupportedTransactionType);

    txn.type = kEip2930TransactionType;
    CHECK(pre_validate_transaction(txn, EVMC_ISTANBUL, config, base_fee_per_gas) ==
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_BERLIN, config, base_fee_per_gas) !=
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, config, base_fee_per_gas) !=
          ValidationResult::kUnsupportedTransactionType);

    txn.type = kEip1559TransactionType;
    CHECK(pre_validate_transaction(txn, EVMC_ISTANBUL, config, base_fee_per_gas) ==
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_BERLIN, config, base_fee_per_gas) ==
          ValidationResult::kUnsupportedTransactionType);
    CHECK(pre_validate_transaction(txn, EVMC_LONDON, config, base_fee_per_gas) !=
          ValidationResult::kUnsupportedTransactionType);
}

}  // namespace silkworm
