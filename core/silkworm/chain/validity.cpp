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

#include <cassert>

#include <ethash/ethash.hpp>

#include <silkworm/common/endian.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/trie/vector_root.hpp>

#include "difficulty.hpp"
#include "intrinsic_gas.hpp"
#include "protocol_param.hpp"

namespace silkworm {

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

static std::optional<BlockHeader> get_parent(const StateBuffer& state, const BlockHeader& header) {
    return state.read_header(header.number - 1, header.parent_hash);
}

// https://eips.ethereum.org/EIPS/eip-1559
static std::optional<intx::uint256> expected_base_fee_per_gas(const BlockHeader& header, const BlockHeader& parent,
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

ValidationResult validate_block_header(const BlockHeader& header, const StateBuffer& state, const ChainConfig& config) {
    if (header.gas_used > header.gas_limit) {
        return ValidationResult::kGasAboveLimit;
    }

    if (header.gas_limit < 5000) {
        return ValidationResult::kInvalidGasLimit;
    }

    // https://github.com/ethereum/go-ethereum/blob/v1.9.25/consensus/ethash/consensus.go#L267
    // https://eips.ethereum.org/EIPS/eip-1985
    if (header.gas_limit > 0x7fffffffffffffff) {
        return ValidationResult::kInvalidGasLimit;
    }

    if (header.extra_data.length() > 32) {
        return ValidationResult::kExtraDataTooLong;
    }

    const std::optional<BlockHeader> parent{get_parent(state, header)};
    if (!parent) {
        return ValidationResult::kUnknownParent;
    }

    if (header.timestamp <= parent->timestamp) {
        return ValidationResult::kInvalidTimestamp;
    }

    uint64_t parent_gas_limit{parent->gas_limit};
    if (header.number == config.revision_block(EVMC_LONDON)) {
        parent_gas_limit = parent->gas_limit * param::kElasticityMultiplier;  // EIP-1559
    }

    const uint64_t gas_delta{header.gas_limit > parent_gas_limit ? header.gas_limit - parent_gas_limit
                                                                 : parent_gas_limit - header.gas_limit};
    if (gas_delta >= parent_gas_limit / 1024) {
        return ValidationResult::kInvalidGasLimit;
    }

    const bool parent_has_uncles{parent->ommers_hash != kEmptyListHash};
    const intx::uint256 difficulty{canonical_difficulty(header.number, header.timestamp, parent->difficulty,
                                                        parent->timestamp, parent_has_uncles, config)};
    if (difficulty != header.difficulty) {
        return ValidationResult::kWrongDifficulty;
    }

    // https://eips.ethereum.org/EIPS/eip-779
    if (config.dao_block && *config.dao_block <= header.number && header.number <= *config.dao_block + 9) {
        static const Bytes kDaoExtraData{*from_hex("0x64616f2d686172642d666f726b")};
        if (header.extra_data != kDaoExtraData) {
            return ValidationResult::kWrongDaoExtraData;
        }
    }

    if (header.base_fee_per_gas != expected_base_fee_per_gas(header, *parent, config)) {
        return ValidationResult::kWrongBaseFee;
    }

    // Ethash PoW verification
    if (config.seal_engine == SealEngineType::kEthash) {

        auto epoch_number{header.number / ethash::epoch_length};
        auto epoch_context{ethash::create_epoch_context(static_cast<int>(epoch_number))};

        auto boundary256{header.boundary()};
        auto seal_hash(header.hash(/*for_sealing =*/true));
        ethash::hash256 sealh256{*reinterpret_cast<ethash::hash256*>(seal_hash.bytes)};
        ethash::hash256 mixh256{};
        std::memcpy(mixh256.bytes, header.mix_hash.bytes, 32);

        uint64_t nonce{endian::load_big_u64(header.nonce.data())};
        return ethash::verify(*epoch_context, sealh256, mixh256, nonce, boundary256) ? ValidationResult::kOk
                                                                                     : ValidationResult::kInvalidSeal;
    }

    return ValidationResult::kOk;
}

// See [YP] Section 11.1 "Ommer Validation"
static bool is_kin(const BlockHeader& branch_header, const BlockHeader& mainline_header,
                   const evmc::bytes32& mainline_hash, unsigned n, const StateBuffer& state,
                   std::vector<BlockHeader>& old_ommers) {
    if (n == 0 || branch_header == mainline_header) {
        return false;
    }

    std::optional<BlockBody> mainline_body{state.read_body(mainline_header.number, mainline_hash)};
    if (!mainline_body) {
        return false;
    }
    old_ommers.insert(old_ommers.end(), mainline_body->ommers.begin(), mainline_body->ommers.end());

    std::optional<BlockHeader> mainline_parent{get_parent(state, mainline_header)};
    std::optional<BlockHeader> branch_parent{get_parent(state, branch_header)};

    if (!mainline_parent) {
        return false;
    }

    bool siblings{branch_parent == mainline_parent};
    if (siblings) {
        return true;
    }

    return is_kin(branch_header, *mainline_parent, mainline_header.parent_hash, n - 1, state, old_ommers);
}

ValidationResult pre_validate_block(const Block& block, const StateBuffer& state, const ChainConfig& config) {
    const BlockHeader& header{block.header};

    if (ValidationResult err{validate_block_header(header, state, config)}; err != ValidationResult::kOk) {
        return err;
    }

    Bytes ommers_rlp;
    rlp::encode(ommers_rlp, block.ommers);
    ethash::hash256 ommers_hash{keccak256(ommers_rlp)};
    if (full_view(ommers_hash.bytes) != full_view(header.ommers_hash)) {
        return ValidationResult::kWrongOmmersHash;
    }

    static constexpr auto kEncoder = [](Bytes& to, const Transaction& txn) {
        rlp::encode(to, txn, /*for_signing=*/false, /*wrap_eip2718_into_array=*/false);
    };

    evmc::bytes32 txn_root{trie::root_hash(block.transactions, kEncoder)};
    if (txn_root != header.transactions_root) {
        return ValidationResult::kWrongTransactionsRoot;
    }

    if (block.ommers.size() > 2) {
        return ValidationResult::kTooManyOmmers;
    }

    if (block.ommers.size() == 2 && block.ommers[0] == block.ommers[1]) {
        return ValidationResult::kDuplicateOmmer;
    }

    std::optional<BlockHeader> parent{get_parent(state, header)};

    for (const BlockHeader& ommer : block.ommers) {
        if (ValidationResult err{validate_block_header(ommer, state, config)}; err != ValidationResult::kOk) {
            return ValidationResult::kInvalidOmmerHeader;
        }
        std::vector<BlockHeader> old_ommers;
        if (!is_kin(ommer, *parent, header.parent_hash, 6, state, old_ommers)) {
            return ValidationResult::kNotAnOmmer;
        }
        for (const BlockHeader& oo : old_ommers) {
            if (oo == ommer) {
                return ValidationResult::kDuplicateOmmer;
            }
        }
    }

    for (const Transaction& txn : block.transactions) {
        ValidationResult err{pre_validate_transaction(txn, header.number, config, header.base_fee_per_gas)};
        if (err != ValidationResult::kOk) {
            return err;
        }
    }

    return ValidationResult::kOk;
}

}  // namespace silkworm
