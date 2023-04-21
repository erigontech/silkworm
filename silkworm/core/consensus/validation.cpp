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

#include <silkworm/core/chain/intrinsic_gas.hpp>
#include <silkworm/core/chain/protocol_param.hpp>
#include <silkworm/core/common/cast.hpp>
#include <silkworm/core/crypto/secp256k1n.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/core/trie/vector_root.hpp>

namespace silkworm::consensus {

bool transaction_type_is_supported(Transaction::Type type, evmc_revision rev) {
    static constexpr evmc_revision kMinRevisionByType[]{
        EVMC_FRONTIER,  // kLegacy
        EVMC_BERLIN,    // kEip2930
        EVMC_LONDON,    // kEip1559
        EVMC_CANCUN,    // kEip4844
    };
    const auto n{static_cast<std::size_t>(type)};
    return n < std::size(kMinRevisionByType) && rev >= kMinRevisionByType[n];
}

ValidationResult pre_validate_transaction(const Transaction& txn, const evmc_revision rev, const uint64_t chain_id,
                                          const std::optional<intx::uint256>& base_fee_per_gas,
                                          const std::optional<intx::uint256>& data_gas_price) {
    if (txn.chain_id.has_value()) {
        if (rev < EVMC_SPURIOUS_DRAGON || txn.chain_id.value() != chain_id) {
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
    if (rev >= EVMC_SHANGHAI && contract_creation && txn.data.size() > param::kMaxInitCodeSize) {
        return ValidationResult::kMaxInitCodeSizeExceeded;
    }

    // EIP-4844: Shard Blob Transactions
    if (txn.type == Transaction::Type::kEip4844) {
        if (txn.blob_versioned_hashes.empty()) {
            return ValidationResult::kNoBlobs;
        }
        for (const Hash& h : txn.blob_versioned_hashes) {
            if (h.bytes[0] != param::kBlobCommitmentVersionKzg) {
                return ValidationResult::kWrongBlobCommitmentVersion;
            }
        }
        SILKWORM_ASSERT(txn.max_fee_per_data_gas);
        SILKWORM_ASSERT(data_gas_price);
        if (txn.max_fee_per_data_gas < data_gas_price) {
            return ValidationResult::kMaxFeePerDataGasTooLow;
        }
        // TODO(yperbasis): There is an equal amount of versioned hashes, kzg commitments and blobs.
        // The KZG commitments hash to the versioned hashes, i.e. kzg_to_versioned_hash(kzg[i]) == versioned_hash[i]
        // The KZG commitments match the blob contents.
    }

    return ValidationResult::kOk;
}

ValidationResult pre_validate_transactions(const Block& block, const ChainConfig& config) {
    const BlockHeader& header{block.header};
    const evmc_revision rev{config.revision(header.number, header.timestamp)};
    const std::optional<intx::uint256> data_gas_price{header.data_gas_price()};

    for (const Transaction& txn : block.transactions) {
        ValidationResult err{pre_validate_transaction(txn, rev, config.chain_id,
                                                      header.base_fee_per_gas, data_gas_price)};
        if (err != ValidationResult::kOk) {
            return err;
        }
    }

    return ValidationResult::kOk;
}

std::optional<intx::uint256> expected_base_fee_per_gas(const BlockHeader& parent, const evmc_revision rev) {
    if (rev < EVMC_LONDON) {
        return std::nullopt;
    }

    if (!parent.base_fee_per_gas) {
        return param::kInitialBaseFee;
    }

    const uint64_t parent_gas_target{parent.gas_limit / param::kElasticityMultiplier};
    const intx::uint256& parent_base_fee_per_gas{*parent.base_fee_per_gas};

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

std::optional<intx::uint256> calc_excess_data_gas(const BlockHeader& parent,
                                                  std::size_t num_blobs,
                                                  const evmc_revision rev) {
    if (rev < EVMC_CANCUN) {
        return std::nullopt;
    }

    const uint64_t consumed_data_gas{num_blobs * param::kDataGasPerBlob};
    const intx::uint256 parent_excess_data_gas{parent.excess_data_gas.value_or(0)};

    if (parent_excess_data_gas + consumed_data_gas < param::kTargetDataGasPerBlock) {
        return 0;
    } else {
        return parent_excess_data_gas + consumed_data_gas - param::kTargetDataGasPerBlock;
    }
}

evmc::bytes32 compute_transaction_root(const BlockBody& body) {
    static constexpr auto kEncoder = [](Bytes& to, const Transaction& txn) {
        rlp::encode(to, txn, /*for_signing=*/false, /*wrap_eip2718_into_string=*/false);
    };
    return trie::root_hash(body.transactions, kEncoder);
}

evmc::bytes32 compute_ommers_hash(const BlockBody& body) {
    if (body.ommers.empty()) {
        return kEmptyListHash;
    }

    Bytes ommers_rlp;
    rlp::encode(ommers_rlp, body.ommers);
    return bit_cast<evmc_bytes32>(keccak256(ommers_rlp));
}

}  // namespace silkworm::consensus
