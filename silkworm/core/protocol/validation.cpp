// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "validation.hpp"

#include <bit>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/crypto/secp256k1n.hpp>
#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/core/trie/vector_root.hpp>

#include "intrinsic_gas.hpp"
#include "param.hpp"
#include "silkworm/core/types/eip_7685_requests.hpp"

namespace silkworm::protocol {

bool transaction_type_is_supported(TransactionType type, evmc_revision rev) {
    static constexpr evmc_revision kMinRevisionByType[]{
        EVMC_FRONTIER,  // kLegacy
        EVMC_BERLIN,    // kAccessList
        EVMC_LONDON,    // kDynamicFee
        EVMC_CANCUN,    // kBlob
        EVMC_PRAGUE,    // kSetCode
    };
    const auto i{static_cast<size_t>(type)};
    return i < std::size(kMinRevisionByType) && rev >= kMinRevisionByType[i];
}

ValidationResult pre_validate_transaction(const Transaction& txn, const evmc_revision rev, const uint64_t chain_id,
                                          const std::optional<intx::uint256>& base_fee_per_gas,
                                          const std::optional<intx::uint256>& blob_gas_price) {
    if (const auto common_check = pre_validate_common_base(txn, rev, chain_id); common_check != ValidationResult::kOk) {
        return common_check;
    }

    if (!is_valid_signature(txn.r, txn.s, rev >= EVMC_HOMESTEAD)) {
        return ValidationResult::kInvalidSignature;
    }

    if (rev >= EVMC_LONDON) {
        if (base_fee_per_gas.has_value() && txn.max_fee_per_gas < base_fee_per_gas.value()) {
            return ValidationResult::kMaxFeeLessThanBase;
        }

        // https://github.com/ethereum/EIPs/pull/3594
        if (txn.max_priority_fee_per_gas > txn.max_fee_per_gas) {
            return ValidationResult::kMaxPriorityFeeGreaterThanMax;
        }
    }

    if (const auto forks_check = pre_validate_common_forks(txn, rev, blob_gas_price); forks_check != ValidationResult::kOk) {
        return forks_check;
    }

    return ValidationResult::kOk;
}

ValidationResult validate_transaction(const Transaction& txn, const IntraBlockState& state,
                                      uint64_t available_gas) noexcept {
    const std::optional<evmc::address> sender{txn.sender()};
    if (!sender) {
        return ValidationResult::kInvalidSignature;
    }

    if (state.get_code_hash(*sender) != kEmptyHash) {
        const auto code = state.get_code(*sender);
        if (!eip7702::is_code_delegated(code)) {
            return ValidationResult::kSenderNoEOA;  // EIP-3607
        }
    }

    const uint64_t nonce{state.get_nonce(*sender)};
    if (nonce != txn.nonce) {
        return ValidationResult::kWrongNonce;
    }

    // See YP, Eq (61) in Section 6.2 "Execution"
    const intx::uint512 v0{txn.maximum_gas_cost() + txn.value};
    if (state.get_balance(*sender) < v0) {
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

ValidationResult validate_call_precheck(const Transaction& txn, const EVM& evm) noexcept {
    const std::optional sender{txn.sender()};
    if (!sender) {
        return ValidationResult::kInvalidSignature;
    }

    if (const auto common_check = pre_validate_common_base(txn, evm.revision(), evm.config().chain_id); common_check != ValidationResult::kOk) {
        return common_check;
    }

    if (evm.revision() >= EVMC_LONDON) {
        if (txn.max_fee_per_gas > 0 || txn.max_priority_fee_per_gas > 0) {
            if (txn.max_fee_per_gas < txn.max_priority_fee_per_gas) {
                return ValidationResult::kMaxPriorityFeeGreaterThanMax;
            }

            if (txn.max_fee_per_gas < evm.block().header.base_fee_per_gas) {
                return ValidationResult::kMaxFeeLessThanBase;
            }
        }
    }

    if (const auto forks_check = pre_validate_common_forks(txn, evm.revision(), evm.block().header.blob_gas_price()); forks_check != ValidationResult::kOk) {
        return forks_check;
    }

    return ValidationResult::kOk;
}

ValidationResult pre_validate_common_base(const Transaction& txn, evmc_revision revision, uint64_t chain_id) noexcept {
    if (txn.chain_id.has_value()) {
        if (revision < EVMC_SPURIOUS_DRAGON) {
            // EIP-155 transaction before EIP-155 was activated
            return ValidationResult::kUnsupportedTransactionType;
        }
        if (txn.chain_id.value() != chain_id) {
            return ValidationResult::kWrongChainId;
        }
    }

    if (!transaction_type_is_supported(txn.type, revision)) {
        return ValidationResult::kUnsupportedTransactionType;
    }

    const intx::uint128 g0{intrinsic_gas(txn, revision)};
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

    return ValidationResult::kOk;
}

ValidationResult pre_validate_common_forks(const Transaction& txn, const evmc_revision rev, const std::optional<intx::uint256>& blob_gas_price) noexcept {
    // EIP-3860: Limit and meter initcode
    const bool contract_creation{!txn.to};
    if (rev >= EVMC_SHANGHAI && contract_creation && txn.data.size() > kMaxInitCodeSize) {
        return ValidationResult::kMaxInitCodeSizeExceeded;
    }

    if (rev >= EVMC_CANCUN) {
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
                return ValidationResult::kProhibitedContractCreation;
            }
        }
    }

    if (rev >= EVMC_PRAGUE) {
        // EIP-7702
        if (txn.type == TransactionType::kSetCode) {
            // Contract creation is disallowed for SetCode transactions
            if (contract_creation) {
                return ValidationResult::kProhibitedContractCreation;
            }
            if (std::empty(txn.authorizations)) {
                return ValidationResult::kEmptyAuthorizations;
            }
        }
        // EIP-7623
        const auto floor_cost = protocol::floor_cost(txn);
        if (txn.gas_limit < floor_cost) {
            return ValidationResult::kFloorCost;
        }
    }
    return ValidationResult::kOk;
}

ValidationResult validate_call_funds(const Transaction& txn, const EVM& evm, const intx::uint256& owned_funds, bool bailout) noexcept {
    const intx::uint256 base_fee{evm.block().header.base_fee_per_gas.value_or(0)};
    const intx::uint256 effective_gas_price{txn.max_fee_per_gas >= evm.block().header.base_fee_per_gas ? txn.effective_gas_price(base_fee)
                                                                                                       : txn.max_priority_fee_per_gas};

    intx::uint512 required_funds = compute_call_cost(txn, effective_gas_price, evm);
    // EIP-7623 Increase calldata cost
    if (evm.revision() >= EVMC_PRAGUE) {
        const auto floor_cost = protocol::floor_cost(txn);
        const intx::uint512 gas_limit = std::max(txn.gas_limit, floor_cost);
        required_funds = std::max(required_funds, gas_limit * effective_gas_price);
    }
    const intx::uint256 value = bailout ? 0 : txn.value;
    if (owned_funds < required_funds + value) {
        return ValidationResult::kInsufficientFunds;
    }
    return ValidationResult::kOk;
}

intx::uint256 compute_call_cost(const Transaction& txn, const intx::uint256& effective_gas_price, const EVM& evm) {
    // EIP-1559 normal gas cost
    intx::uint256 required_funds;
    if (txn.max_fee_per_gas > 0 || txn.max_priority_fee_per_gas > 0) {
        // This method should be called after check (max_fee and base_fee) present in pre_check() method
        required_funds = txn.gas_limit * effective_gas_price;
    } else {
        required_funds = 0;
    }

    // EIP-4844 blob gas cost (calc_data_fee)
    if (evm.block().header.blob_gas_used && evm.revision() >= EVMC_CANCUN) {
        // compute blob fee for eip-4844 data blobs if any
        const intx::uint256 blob_gas_price{evm.block().header.blob_gas_price().value_or(0)};
        required_funds += txn.total_blob_gas() * blob_gas_price;
    }

    return required_funds;
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
    }

    const intx::uint256 gas_used_delta{parent_gas_target - parent.gas_used};
    const intx::uint256 base_fee_per_gas_delta{parent_base_fee_per_gas * gas_used_delta / parent_gas_target /
                                               kBaseFeeMaxChangeDenominator};
    if (parent_base_fee_per_gas > base_fee_per_gas_delta) {
        return parent_base_fee_per_gas - base_fee_per_gas_delta;
    }
    return 0;
}

uint64_t calc_excess_blob_gas(const BlockHeader& parent, evmc_revision revision) {
    const uint64_t parent_excess_blob_gas{parent.excess_blob_gas.value_or(0)};
    const uint64_t consumed_blob_gas{parent.blob_gas_used.value_or(0)};

    // EIP-7691: Blob throughput increase
    const auto target_block_gas_per_block = revision >= EVMC_PRAGUE ? kTargetBlobGasPerBlockPrague : kTargetBlobGasPerBlock;
    if (parent_excess_blob_gas + consumed_blob_gas < target_block_gas_per_block) {
        return 0;
    }
    return parent_excess_blob_gas + consumed_blob_gas - target_block_gas_per_block;
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

ValidationResult validate_requests_root(const BlockHeader& header, const std::vector<Log>& logs, EVM& evm) {
    FlatRequests requests;

    // Dequeue deposit requests by parsing logs
    requests.extract_deposits_from_logs(logs);

    // Withdrawal requests
    {
        Transaction system_txn{};
        system_txn.type = TransactionType::kSystem;
        system_txn.to = kWithdrawalRequestAddress;
        system_txn.data = Bytes{};
        system_txn.set_sender(kSystemAddress);
        const auto withdrawals = evm.execute(system_txn, kSystemCallGasLimit);
        evm.state().destruct_touched_dead();
        requests.add_request(FlatRequestType::kWithdrawalRequest, withdrawals.data);
    }

    // Consolidation requests
    {
        Transaction system_txn{};
        system_txn.type = TransactionType::kSystem;
        system_txn.to = kConsolidationRequestAddress;
        system_txn.data = Bytes{};
        system_txn.set_sender(kSystemAddress);
        const auto consolidations = evm.execute(system_txn, kSystemCallGasLimit);
        evm.state().destruct_touched_dead();
        requests.add_request(FlatRequestType::kConsolidationRequest, consolidations.data);
    }

    const auto computed_hash = requests.calculate_sha256();

    if (computed_hash != header.requests_hash) {
        return ValidationResult::kRequestsRootMismatch;
    }

    return ValidationResult::kOk;
}

}  // namespace silkworm::protocol
