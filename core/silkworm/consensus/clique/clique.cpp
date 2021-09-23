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

#include "clique.hpp"

#include <ctime>

#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/trie/vector_root.hpp>

namespace silkworm::consensus {

ValidationResult Clique::pre_validate_block(const Block& block, State& state, const ChainConfig& config) {
    return validate_block_header(block.header, state, config);
}

ValidationResult Clique::validate_block_header(const BlockHeader& header, State& state, const ChainConfig&) {
    auto now{std::time(nullptr)};
    if (header.timestamp > static_cast<uint64_t>(now)) {
        return ValidationResult::kFutureBlock;
    }

    /* Common checks for all block types (regular and checkpoint) */

    // Nonces must be always 0x00..0 or 0xff..f, zeroes enforced on checkpoints
    if (header.nonce != kNonceAuthVote && header.nonce != kNonceDropVote) {
        return ValidationResult::kInvalidVote;
    }

    // Ensure that the block doesn't contain any uncles which are meaningless in PoA
    if (header.ommers_hash != kEmptyListHash) {
        return ValidationResult::kWrongOmmersHash;
    }

    // Ensure that the mix digest is zero as we don't have fork protection currently
    if (header.mix_hash) {
        return ValidationResult::kInvalidMixHash;
    }

    // Check that the extra-data contains both the vanity and signature
    if (header.extra_data.size() < (kHashLength + kSignatureLength + 1)) {
        return ValidationResult::kMissingVanity;
    }

    // Checkpoint blocks
    bool checkpoint{header.number % clique_config_.epoch == 0};
    if (checkpoint) {
        if (header.beneficiary) {
            return ValidationResult::kInvalidCheckpointBeneficiary;
        }
        if (header.nonce != kNonceDropVote) {
            return ValidationResult::kInvalidVote;
        }
    }

    // Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
    uint64_t signers_length{header.extra_data.size() - kHashLength - kSignatureLength - 1};
    if (!checkpoint && signers_length != 0) {
        return ValidationResult::kUnauthorizedSigner;
    }
    if (checkpoint && (signers_length % kAddressLength) != 0) {
        return ValidationResult::kMissingSigner;
    }

    // Ensure that the block's difficulty is meaningful (may not be correct at this point)
    if (header.number > 0) {
        auto parent{state.read_header(header.number - 1, header.parent_hash)};
        if (parent == std::nullopt) {
            return ValidationResult::kUnknownParent;
        }
        if (parent->timestamp > header.timestamp - clique_config_.period) {
            return ValidationResult::kInvalidTimestamp;
        }
        if (header.difficulty != kDiffInTurn && header.difficulty != kDiffNoTurn) {
            return ValidationResult::kWrongDifficulty;
        }
    }

    // All basic checks passed, verify cascading fields
    if (header.number == 0) {
        std::vector<evmc::address> signers;
        size_t signers_count{(header.extra_data.size() - kHashLength - kSignatureLength - 1) / kAddressLength};
        for (size_t i = 0; i < signers_count; i++) {
            evmc::address signer;
            std::memcpy(signer.bytes, &header.extra_data[kHashLength + (i * kAddressLength)], kAddressLength);
            signers.push_back(signer);
        }
        last_snapshot_ = CliqueSnapshot{header.number, header.hash(), signers, {}};
        state.write_snapshot(header.number, header.hash(), last_snapshot_);
        return ValidationResult::kOk;
    } else if (!last_snapshot_.get_hash()) {
        // If last snapshot is not set, find it from the database and initialize it
        auto current_header{header};
        std::vector<BlockHeader> pending_blocks;

        while (current_header.number % clique_config_.epoch != 0) {
            pending_blocks.push_back(current_header);
            auto parent{state.read_header(current_header.number - 1, current_header.parent_hash)};
            if (parent == std::nullopt) {
                return ValidationResult::kUnknownParent;
            }
            current_header = *parent;
        }
        std::reverse(pending_blocks.begin(), pending_blocks.end());
        auto db_snapshot{state.read_snapshot(current_header.number, current_header.hash())};
        if (db_snapshot.has_value()) {
            last_snapshot_ = db_snapshot.value();
        }
        for (const auto& h : pending_blocks) {
            auto signer{get_signer_from_clique_header(h)};

            if (signer == std::nullopt) {
                return ValidationResult::kInvalidVote;
            }

            auto err{last_snapshot_.add_header(h, *signer, clique_config_)};
            if (err != ValidationResult::kOk) {
                return err;
            }
        }
        return ValidationResult::kOk;
    } else {
        auto signer{get_signer_from_clique_header(header)};

        if (signer == std::nullopt) {
            return ValidationResult::kInvalidVote;
        }

        auto err{last_snapshot_.add_header(header, *signer, clique_config_)};
        if (err != ValidationResult::kOk) {
            return err;
        }
        if (checkpoint) {
            state.write_snapshot(last_snapshot_.get_block_number(), last_snapshot_.get_hash(), last_snapshot_);
        }
        return last_snapshot_.verify_seal(header, *signer);
    }
}

// There are no rewards in Clique POA consensus
void Clique::apply_rewards(IntraBlockState&, const Block&, const evmc_revision&) {}

evmc::address Clique::get_beneficiary(const BlockHeader& header) {
    (void)header;
    return {};
}

// taking the header not by reference is intentional
std::optional<evmc::address> Clique::get_signer_from_clique_header(BlockHeader header) {
    auto extra_data_size{header.extra_data.size()};
    // Extract signature first
    Bytes signature(kSignatureLength, '\0');
    std::memcpy(&signature[0], &header.extra_data[extra_data_size - 65], kSignatureLength);
    auto v{header.extra_data.back()};
    if (v == 27 || v == 28) {
        v -= 27;
    }

    // Generate Sealing Hash for Clique
    // for_sealing = false, with signature in extra_data
    header.extra_data = header.extra_data.substr(0, extra_data_size - kSignatureLength - 1);
    auto header_hash{header.hash()};

    // Run Ecrecover and get public key
    auto recovered{ecdsa::recover(full_view(header_hash), signature, v)};
    if (!recovered.has_value() || recovered->at(0) != 4u) {
        return std::nullopt;
    }
    auto hash{keccak256(recovered->substr(1))};
    // Convert public key to address
    evmc::address signer{};
    std::memcpy(signer.bytes, &hash.bytes[12], kAddressLength);
    return signer;
}

}  // namespace silkworm::consensus