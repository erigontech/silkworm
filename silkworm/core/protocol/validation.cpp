/*
   Copyright 2022 The Silkworm Authors

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

#include <bit>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/crypto/secp256k1n.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/core/trie/vector_root.hpp>

#include "intrinsic_gas.hpp"
#include "param.hpp"

namespace silkworm::protocol {

bool transaction_type_is_supported(TransactionType type, evmc_revision rev) {
    static constexpr evmc_revision kMinRevisionByType[]{
        EVMC_FRONTIER,  // kLegacy
        EVMC_BERLIN,    // kAccessList
        EVMC_LONDON,    // kDynamicFee
        EVMC_CANCUN,    // kBlob
    };
    const auto i{static_cast<std::size_t>(type)};
    return i < std::size(kMinRevisionByType) && rev >= kMinRevisionByType[i];
}

ValidationResult pre_validate_transaction(const Transaction& txn, const evmc_revision rev, const uint64_t chain_id,
                                          const std::optional<intx::uint256>& base_fee_per_gas,
                                          const std::optional<intx::uint256>& blob_gas_price) {
    if (txn.chain_id.has_value()) {
        if (rev < EVMC_SPURIOUS_DRAGON) {
            // EIP-155 transaction before EIP-155 was activated
            return ValidationResult::kUnsupportedTransactionType;
        }
        if (txn.chain_id.value() != chain_id) {
            return ValidationResult::kWrongChainId;
        }
    }

    if (!transaction_type_is_supported(txn.type, rev)) {
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
        if (!is_valid_signature(txn.r, txn.s, rev >= EVMC_HOMESTEAD)) {
            return ValidationResult::kInvalidSignature;
        }
    }

    const intx::uint128 g0{intrinsic_gas(txn, rev)};
    if (txn.gas_limit < g0) {
        return ValidationResult::kIntrinsicGas;
    }

    if (intx::count_significant_bytes(txn.maximum_gas_cost()) > 32) {
        return ValidationResult::kInsufficientFunds;
    }

    // EIP-2681: Limit account nonce to 2^64-1
    if (txn.nonce >= UINT64_MAX) {
        return ValidationResult::kNonceTooHigh;
    }

    // EIP-3860: Limit and meter initcode
    const bool contract_creation{!txn.to};
    if (rev >= EVMC_SHANGHAI && contract_creation && txn.data.size() > kMaxInitCodeSize) {
        return ValidationResult::kMaxInitCodeSizeExceeded;
    }

    // EIP-4844: Shard Blob Transactions
    if (txn.type == TransactionType::kBlob) {
        if (txn.blob_versioned_hashes.empty()) {
            return ValidationResult::kNoBlobs;
        }
        for (const Hash& h : txn.blob_versioned_hashes) {
            if (h.bytes[0] != kBlobCommitmentVersionKzg) {
                return ValidationResult::kWrongBlobCommitmentVersion;
            }
        }
        SILKWORM_ASSERT(blob_gas_price);
        if (txn.max_fee_per_blob_gas < blob_gas_price) {
            return ValidationResult::kMaxFeePerBlobGasTooLow;
        }
        if (!txn.to) {
            return ValidationResult::kBlobCreateTransaction;
        }
    }

    return ValidationResult::kOk;
}

ValidationResult validate_transaction(const Transaction& txn, const IntraBlockState& state,
                                      uint64_t available_gas) noexcept {
    if (!txn.from) {
        return ValidationResult::kMissingSender;
    }

    if (state.get_code_hash(*txn.from) != kEmptyHash) {
        return ValidationResult::kSenderNoEOA;  // EIP-3607
    }

    const uint64_t nonce{state.get_nonce(*txn.from)};
    if (nonce != txn.nonce) {
        return ValidationResult::kWrongNonce;
    }

    // See YP, Eq (61) in Section 6.2 "Execution"
    const intx::uint512 v0{txn.maximum_gas_cost() + txn.value};
    if (state.get_balance(*txn.from) < v0) {
        return ValidationResult::kInsufficientFunds;
    }

    if (available_gas < txn.gas_limit) {
        // Corresponds to the final condition of Eq (58) in Yellow Paper Section 6.2 "Execution".
        // The sum of the transaction’s gas limit and the gas utilized in this block prior
        // must be no greater than the block’s gas limit.
        return ValidationResult::kBlockGasLimitExceeded;
    }

    return ValidationResult::kOk;
}

ValidationResult pre_validate_transactions(const Block& block, const ChainConfig& config) {
    const BlockHeader& header{block.header};
    const evmc_revision rev{config.revision(header.number, header.timestamp)};
    const std::optional<intx::uint256> blob_gas_price{header.blob_gas_price()};

    for (const Transaction& txn : block.transactions) {
        ValidationResult err{pre_validate_transaction(txn, rev, config.chain_id,
                                                      header.base_fee_per_gas, blob_gas_price)};
        if (err != ValidationResult::kOk) {
            return err;
        }
    }

    return ValidationResult::kOk;
}

intx::uint256 expected_base_fee_per_gas(const BlockHeader& parent) {
    if (!parent.base_fee_per_gas) {
        return kInitialBaseFee;
    }

    const uint64_t parent_gas_target{parent.gas_limit / kElasticityMultiplier};
    const intx::uint256& parent_base_fee_per_gas{*parent.base_fee_per_gas};

    if (parent.gas_used == parent_gas_target) {
        return parent_base_fee_per_gas;
    }

    if (parent.gas_used > parent_gas_target) {
        const intx::uint256 gas_used_delta{parent.gas_used - parent_gas_target};
        intx::uint256 base_fee_per_gas_delta{parent_base_fee_per_gas * gas_used_delta / parent_gas_target /
                                             kBaseFeeMaxChangeDenominator};
        if (base_fee_per_gas_delta < 1) {
            base_fee_per_gas_delta = 1;
        }
        return parent_base_fee_per_gas + base_fee_per_gas_delta;
    } else {
        const intx::uint256 gas_used_delta{parent_gas_target - parent.gas_used};
        const intx::uint256 base_fee_per_gas_delta{parent_base_fee_per_gas * gas_used_delta / parent_gas_target /
                                                   kBaseFeeMaxChangeDenominator};
        if (parent_base_fee_per_gas > base_fee_per_gas_delta) {
            return parent_base_fee_per_gas - base_fee_per_gas_delta;
        } else {
            return 0;
        }
    }
}

uint64_t calc_excess_blob_gas(const BlockHeader& parent) {
    const uint64_t parent_excess_blob_gas{parent.excess_blob_gas.value_or(0)};
    const uint64_t consumed_blob_gas{parent.blob_gas_used.value_or(0)};

    if (parent_excess_blob_gas + consumed_blob_gas < kTargetBlobGasPerBlock) {
        return 0;
    } else {
        return parent_excess_blob_gas + consumed_blob_gas - kTargetBlobGasPerBlock;
    }
}

evmc::bytes32 compute_transaction_root(const BlockBody& body) {
    static constexpr auto kEncoder = [](Bytes& to, const Transaction& txn) {
        rlp::encode(to, txn, /*wrap_eip2718_into_string=*/false);
    };
    return trie::root_hash(body.transactions, kEncoder);
}

std::optional<evmc::bytes32> compute_withdrawals_root(const BlockBody& body) {
    if (!body.withdrawals) {
        return std::nullopt;
    }

    static constexpr auto kEncoder = [](Bytes& to, const Withdrawal& w) {
        rlp::encode(to, w);
    };
    return trie::root_hash(*body.withdrawals, kEncoder);
}

evmc::bytes32 compute_ommers_hash(const BlockBody& body) {
    if (body.ommers.empty()) {
        return kEmptyListHash;
    }

    Bytes ommers_rlp;
    rlp::encode(ommers_rlp, body.ommers);
    return std::bit_cast<evmc_bytes32>(keccak256(ommers_rlp));
}

}  // namespace silkworm::protocol
