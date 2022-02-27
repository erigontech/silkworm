/*
    Copyright 2021-2022 The Silkworm Authors

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

#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/common/as_range.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/rlp/encode_vector.hpp>
#include <silkworm/trie/vector_root.hpp>

namespace silkworm::consensus {

ValidationResult EngineBase::pre_validate_block(const Block& block, const BlockState& state) {
    const BlockHeader& header{block.header};

    if (ValidationResult err{validate_block_header(header, state, /*with_future_timestamp_check=*/true)};
        err != ValidationResult::kOk) {
        return err;
    }

    static constexpr auto kEncoder = [](Bytes& to, const Transaction& txn) {
        rlp::encode(to, txn, /*for_signing=*/false, /*wrap_eip2718_into_array=*/false);
    };

    evmc::bytes32 txn_root{trie::root_hash(block.transactions, kEncoder)};
    if (txn_root != header.transactions_root) {
        return ValidationResult::kWrongTransactionsRoot;
    }

    for (const Transaction& txn : block.transactions) {
        if (ValidationResult err{pre_validate_transaction(txn, header.number, chain_config_, header.base_fee_per_gas)};
            err != ValidationResult::kOk) {
            return err;
        }
    }

    if (block.ommers.empty()) {
        return header.ommers_hash == kEmptyListHash ? ValidationResult::kOk : ValidationResult::kWrongOmmersHash;
    } else if (prohibit_ommers_) {
        return ValidationResult::kTooManyOmmers;
    }

    Bytes ommers_rlp;
    rlp::encode(ommers_rlp, block.ommers);
    ethash::hash256 ommers_hash{keccak256(ommers_rlp)};
    if (ByteView{ommers_hash.bytes} != ByteView{header.ommers_hash}) {
        return ValidationResult::kWrongOmmersHash;
    }

    if (block.ommers.size() > 2) {
        return ValidationResult::kTooManyOmmers;
    }

    if (block.ommers.size() == 2 && block.ommers[0] == block.ommers[1]) {
        return ValidationResult::kDuplicateOmmer;
    }

    std::optional<BlockHeader> parent{get_parent_header(state, header)};

    for (const BlockHeader& ommer : block.ommers) {
        if (ValidationResult err{validate_block_header(ommer, state, /*with_future_timestamp_check=*/false)};
            err != ValidationResult::kOk) {
            return ValidationResult::kInvalidOmmerHeader;
        }
        std::vector<BlockHeader> old_ommers;
        if (!is_kin(ommer, *parent, header.parent_hash, 6, state, old_ommers)) {
            return ValidationResult::kNotAnOmmer;
        }

        if (as_range::find(old_ommers, ommer) != old_ommers.end()) {
            return ValidationResult::kDuplicateOmmer;
        }
    }

    return ValidationResult::kOk;
}

ValidationResult EngineBase::validate_block_header(const BlockHeader& header, const BlockState& state,
                                                   bool with_future_timestamp_check) {
    if (with_future_timestamp_check) {
        const std::time_t now{std::time(nullptr)};
        if (header.timestamp > static_cast<uint64_t>(now)) {
            return ValidationResult::kFutureBlock;
        }
    }

    if (header.gas_used > header.gas_limit) {
        return ValidationResult::kGasAboveLimit;
    }

    if (header.gas_limit < 5000) {
        return ValidationResult::kInvalidGasLimit;
    }

    // https://github.com/ethereum/go-ethereum/blob/v1.9.25/consensus/ethash/consensus.go#L267
    // https://eips.ethereum.org/EIPS/eip-1985
    if (header.gas_limit > INT64_MAX) {
        return ValidationResult::kInvalidGasLimit;
    }

    if (header.extra_data.length() > param::kMaxExtraDataBytes) {
        return ValidationResult::kExtraDataTooLong;
    }

    if (prohibit_ommers_ && header.ommers_hash != kEmptyListHash) {
        return ValidationResult::kWrongOmmersHash;
    }

    const std::optional<BlockHeader> parent{get_parent_header(state, header)};
    if (!parent.has_value()) {
        return ValidationResult::kUnknownParent;
    }

    if (header.timestamp <= parent->timestamp) {
        return ValidationResult::kInvalidTimestamp;
    }

    uint64_t parent_gas_limit{parent->gas_limit};
    if (header.number == chain_config_.revision_block(EVMC_LONDON)) {
        parent_gas_limit = parent->gas_limit * param::kElasticityMultiplier;  // EIP-1559
    }

    const uint64_t gas_delta{header.gas_limit > parent_gas_limit ? header.gas_limit - parent_gas_limit
                                                                 : parent_gas_limit - header.gas_limit};
    if (gas_delta >= parent_gas_limit / 1024) {
        return ValidationResult::kInvalidGasLimit;
    }

    if (ValidationResult res{validate_difficulty(header, *parent)}; res != ValidationResult::kOk) {
        return res;
    }

    // https://eips.ethereum.org/EIPS/eip-779
    if (chain_config_.dao_block.has_value() && chain_config_.dao_block.value() <= header.number &&
        header.number <= chain_config_.dao_block.value() + 9) {
        static const Bytes kDaoExtraData{*from_hex("0x64616f2d686172642d666f726b")};
        if (header.extra_data != kDaoExtraData) {
            return ValidationResult::kWrongDaoExtraData;
        }
    }

    if (header.base_fee_per_gas != expected_base_fee_per_gas(header, parent.value())) {
        return ValidationResult::kWrongBaseFee;
    }

    return validate_seal(header);
}

std::optional<BlockHeader> EngineBase::get_parent_header(const BlockState& state, const BlockHeader& header) {
    if (header.number == 0) {
        return std::nullopt;
    }
    return state.read_header(header.number - 1, header.parent_hash);
}

bool EngineBase::is_kin(const BlockHeader& branch_header, const BlockHeader& mainline_header,
                        const evmc::bytes32& mainline_hash, unsigned int n, const BlockState& state,
                        std::vector<BlockHeader>& old_ommers) {
    if (n == 0 || branch_header == mainline_header) {
        return false;
    }

    BlockBody mainline_body;
    if (!state.read_body(mainline_header.number, mainline_hash, mainline_body)) {
        return false;
    }

    old_ommers.insert(old_ommers.end(), mainline_body.ommers.begin(), mainline_body.ommers.end());

    std::optional<BlockHeader> mainline_parent{get_parent_header(state, mainline_header)};
    if (!mainline_parent) {
        return false;
    }

    std::optional<BlockHeader> branch_parent{get_parent_header(state, branch_header)};
    if (branch_parent == mainline_parent) {
        return true;
    }

    return is_kin(branch_header, mainline_parent.value(), mainline_header.parent_hash, n - 1, state, old_ommers);
}

evmc::address EngineBase::get_beneficiary(const BlockHeader& header) { return header.beneficiary; }

std::optional<intx::uint256> EngineBase::expected_base_fee_per_gas(const BlockHeader& header,
                                                                   const BlockHeader& parent) {
    if (chain_config_.revision(header.number) < EVMC_LONDON) {
        return std::nullopt;
    }

    if (header.number == chain_config_.revision_block(EVMC_LONDON)) {
        return param::kInitialBaseFee;
    }

    const uint64_t parent_gas_target{parent.gas_limit / param::kElasticityMultiplier};

    assert(parent.base_fee_per_gas.has_value());
    const intx::uint256 parent_base_fee_per_gas{parent.base_fee_per_gas.value()};

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

}  // namespace silkworm::consensus
