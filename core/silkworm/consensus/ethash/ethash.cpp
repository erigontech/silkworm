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

#include "ethash.hpp"

#include <ethash/ethash.hpp>

#include <silkworm/chain/difficulty.hpp>
#include <silkworm/chain/intrinsic_gas.hpp>
#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/trie/vector_root.hpp>

namespace silkworm::consensus {

static std::optional<BlockHeader> get_parent(const State& state, const BlockHeader& header) {
    if (header.number == 0) {
        return std::nullopt;
    }
    return state.read_header(header.number - 1, header.parent_hash);
}

ValidationResult Ethash::validate_block_header(const BlockHeader& header, State& state, const ChainConfig& config) {
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
                   const evmc::bytes32& mainline_hash, unsigned n, const State& state,
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

ValidationResult Ethash::pre_validate_block(const Block& block, State& state, const ChainConfig& config) {
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

void Ethash::apply_rewards(IntraBlockState& state, const Block& block, const evmc_revision& revision) {
    intx::uint256 block_reward;
    if (revision >= EVMC_CONSTANTINOPLE) {
        block_reward = param::kBlockRewardConstantinople;
    } else if (revision >= EVMC_BYZANTIUM) {
        block_reward = param::kBlockRewardByzantium;
    } else {
        block_reward = param::kBlockRewardFrontier;
    }

    const uint64_t block_number{block.header.number};
    intx::uint256 miner_reward{block_reward};
    for (const BlockHeader& ommer : block.ommers) {
        intx::uint256 ommer_reward{((8 + ommer.number - block_number) * block_reward) >> 3};
        state.add_to_balance(ommer.beneficiary, ommer_reward);
        miner_reward += block_reward / 32;
    }

    state.add_to_balance(block.header.beneficiary, miner_reward);
}

evmc::address Ethash::get_beneficiary(const BlockHeader& header) { return header.beneficiary; }

}  // namespace silkworm::consensus
