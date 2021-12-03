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

#include "engine.hpp"

#include <silkworm/chain/intrinsic_gas.hpp>
#include <silkworm/consensus/ethash/engine.hpp>
#include <silkworm/consensus/merge/engine.hpp>
#include <silkworm/consensus/noproof/engine.hpp>
#include <silkworm/crypto/ecdsa.hpp>

namespace silkworm::consensus {

void IEngine::finalize(IntraBlockState&, const Block&, evmc_revision) {}

ValidationResult pre_validate_transaction(const Transaction& txn, uint64_t block_number, const ChainConfig& config,
                                          const std::optional<intx::uint256>& base_fee_per_gas) {
    const evmc_revision rev{config.revision(block_number)};

    if (txn.chain_id.has_value()) {
        if (rev < EVMC_SPURIOUS_DRAGON || txn.chain_id.value() != config.chain_id) {
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

    if (base_fee_per_gas.has_value() && txn.max_fee_per_gas < base_fee_per_gas.value()) {
        return ValidationResult::kMaxFeeLessThanBase;
    }

    // https://github.com/ethereum/EIPs/pull/3594
    if (txn.max_priority_fee_per_gas > txn.max_fee_per_gas) {
        return ValidationResult::kMaxPriorityFeeGreaterThanMax;
    }

    /* Should the sender already be present it means the validation of signature already occurred */
    if (!txn.from.has_value()) {
        if (!ecdsa::is_valid_signature(txn.r, txn.s, rev >= EVMC_HOMESTEAD)) {
            return ValidationResult::kInvalidSignature;
        }
    }

    const intx::uint128 g0{intrinsic_gas(txn, rev >= EVMC_HOMESTEAD, rev >= EVMC_ISTANBUL)};
    if (txn.gas_limit < g0) {
        return ValidationResult::kIntrinsicGas;
    }

    // EIP-2681: Limit account nonce to 2^64-1
    if (txn.nonce >= UINT64_MAX) {
        return ValidationResult::kNonceTooHigh;
    }

    return ValidationResult::kOk;
}

std::unique_ptr<IEngine> engine_factory(const ChainConfig& chain_config) {
    if (chain_config.terminal_total_difficulty.has_value()) {
        return std::make_unique<MergeEngine>(chain_config);
    }

    switch (chain_config.seal_engine) {
        case SealEngineType::kEthash:
            return std::make_unique<EthashEngine>(chain_config);
        case SealEngineType::kNoProof:
            return std::make_unique<NoProofEngine>(chain_config);
        default:
            return {};
    }
}

}  // namespace silkworm::consensus
