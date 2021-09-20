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

#include "consensus_engine.hpp"

#include <cassert>

#include <ethash/ethash.hpp>

#include <silkworm/chain/difficulty.hpp>
#include <silkworm/chain/intrinsic_gas.hpp>
#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/consensus/clique/clique.hpp>
#include <silkworm/consensus/ethash/ethash.hpp>
#include <silkworm/crypto/ecdsa.hpp>

namespace silkworm::consensus {

ValidationResult pre_validate_transaction(const Transaction& txn, uint64_t block_number, const ChainConfig& config,
                                          const std::optional<intx::uint256>& base_fee_per_gas) {
    const evmc_revision rev{config.revision(block_number)};

    if (txn.chain_id.has_value()) {
        if (rev < EVMC_SPURIOUS_DRAGON || txn.chain_id != config.chain_id) {
            return ValidationResult::kWrongChainId;
        }
    }

    if (txn.type == Transaction::Type::kEip2930) {
        if (rev < EVMC_BERLIN) {
            return ValidationResult::kUnsupportedTransactionType;
        }
    } else if (txn.type == Transaction::Type::kEip1559) {
        if (rev < EVMC_LONDON) {
            return ValidationResult::kUnsupportedTransactionType;
        }
    } else if (txn.type != Transaction::Type::kLegacy) {
        return ValidationResult::kUnsupportedTransactionType;
    }

    if (base_fee_per_gas.has_value() && txn.max_fee_per_gas < base_fee_per_gas) {
        return ValidationResult::kMaxFeeLessThanBase;
    }

    // https://github.com/ethereum/EIPs/pull/3594
    if (txn.max_priority_fee_per_gas > txn.max_fee_per_gas) {
        return ValidationResult::kMaxPriorityFeeGreaterThanMax;
    }

    if (!ecdsa::is_valid_signature(txn.r, txn.s, rev >= EVMC_HOMESTEAD)) {
        return ValidationResult::kInvalidSignature;
    }

    const intx::uint128 g0{intrinsic_gas(txn, rev >= EVMC_HOMESTEAD, rev >= EVMC_ISTANBUL)};
    if (txn.gas_limit < g0) {
        return ValidationResult::kIntrinsicGas;
    }

    return ValidationResult::kOk;
}

std::optional<intx::uint256> expected_base_fee_per_gas(const BlockHeader& header, const BlockHeader& parent,
                                                       const ChainConfig& config) {
    if (config.revision(header.number) < EVMC_LONDON) {
        return std::nullopt;
    }

    if (header.number == config.revision_block(EVMC_LONDON)) {
        return param::kInitialBaseFee;
    }

    const uint64_t parent_gas_target{parent.gas_limit / param::kElasticityMultiplier};

    assert(parent.base_fee_per_gas.has_value());
    const intx::uint256 parent_base_fee_per_gas{*parent.base_fee_per_gas};

    if (parent.gas_used == parent_gas_target) {
        return parent_base_fee_per_gas;
    }

    if (parent.gas_used > parent_gas_target) {
        const intx::uint256 gas_used_delta{parent.gas_used - parent_gas_target};
        intx::uint256 base_fee_per_gas_delta{parent_base_fee_per_gas * gas_used_delta / parent_gas_target /
                                             param::kBaseFeeMaxChangeDenominator};
        if (base_fee_per_gas_delta < 1) {
            base_fee_per_gas_delta = 1;
        }
        return parent_base_fee_per_gas + base_fee_per_gas_delta;
    } else {
        const intx::uint256 gas_used_delta{parent_gas_target - parent.gas_used};
        const intx::uint256 base_fee_per_gas_delta{parent_base_fee_per_gas * gas_used_delta / parent_gas_target /
                                                   param::kBaseFeeMaxChangeDenominator};
        if (parent_base_fee_per_gas > base_fee_per_gas_delta) {
            return parent_base_fee_per_gas - base_fee_per_gas_delta;
        } else {
            return 0;
        }
    }
}

std::unique_ptr<ConsensusEngine> get_consensus_engine(SealEngineType engine_type) {
    switch (engine_type) {
        case SealEngineType::kEthash:
            return std::make_unique<Ethash>();
        case SealEngineType::kClique:
            return std::make_unique<Clique>(kDefaultCliqueConfig);
        default:
            return std::make_unique<Ethash>();
    }
}

}  // namespace silkworm::consensus
