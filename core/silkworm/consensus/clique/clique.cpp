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

#include <silkworm/trie/vector_root.hpp>
#include <silkworm/chain/intrinsic_gas.hpp>
#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/chain/difficulty.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <iostream>

#include "clique.hpp"

namespace silkworm::consensus {

ValidationResult Clique::pre_validate_block(const Block& block, State& state, const ChainConfig& config) {
    const BlockHeader& header{block.header};

    if (ValidationResult err{validate_block_header(header, state, config)}; err != ValidationResult::kOk) {
        return err;
    }

    return ValidationResult::kOk;
}

ValidationResult Clique::validate_block_header(const BlockHeader& header, State& state, const ChainConfig&) {

	// Checkpoint blocks need to enforce zero beneficiary
	uint64_t checkpoint{header.number % clique_config_.epoch == 0};
	if (checkpoint && header.beneficiary != 0x0000000000000000000000000000000000000000_address) {
		return ValidationResult::kInvalidCheckpointBeneficiary;
	}

	// Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
	if (header.nonce != kNonceAuthorize && header.nonce !=  kNonceUnauthorize) {
		return ValidationResult::kInvalidVote;
	}

	if (checkpoint && header.nonce != kNonceUnauthorize) {
		return ValidationResult::kInvalidVote;
	}

	// Check that the extra-data contains both the vanity and signature
	if (header.extra_data.size() < (kHashLength + kSignatureLength + 1)) {
		return ValidationResult::kMissingVanity;
	}

	// Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
	uint64_t signers_length{header.extra_data.size() - kHashLength - kSignatureLength - 1};
	if (!checkpoint && signers_length != 0) {
		return ValidationResult::kUnhauthorizedSigner;
	}
	if (checkpoint && (signers_length % kAddressLength) != 0) {
		return ValidationResult::kMissingSigner;
	}
	// Ensure that the mix digest is zero as we don't have fork protection currently
	if (header.mix_hash != 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32) {
		return ValidationResult::kWrongNonce;
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if (header.ommers_hash != kEmptyListHash) {
		return ValidationResult::kWrongOmmersHash;
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if (header.number > 0) {
		if (header.difficulty == 0 || (header.difficulty != kDiffInTurn && header.difficulty != kDiffNoTurn)) {
			return ValidationResult::kInvalidGasLimit;
		}
	}

	// All basic checks passed, verify cascading fields
    if (header.number == 0) {
        std::vector<evmc::address> signers;
        size_t signers_count{(header.extra_data.size() - kHashLength - kSignatureLength -1) / kAddressLength};
        for (size_t i = 0; i < signers_count; i++) {
            evmc::address signer;
            std::memcpy(signer.bytes, 
                        &header.extra_data[kHashLength + (i * kAddressLength)],
                        kAddressLength);
            signers.push_back(signer);
        }
        last_snapshot_ = CliqueSnapshot{header.number, header.hash(), signers};
        state.write_snapshot(header.number, header.hash(), last_snapshot_);

        return ValidationResult::kOk;
    } else {
        auto err{last_snapshot_.add_header(header)};

        if (err != ValidationResult::kOk) {
            return err;
        }

        state.write_snapshot(last_snapshot_.get_block_number(), last_snapshot_.get_hash(), last_snapshot_);
        return last_snapshot_.verify_seal(header);
    }
}

// There are no rewards in Clique POA consensus
void Clique::apply_rewards(IntraBlockState&, const Block&, const evmc_revision&) {}

void Clique::assign_transaction_fees(const BlockHeader&, intx::uint256, IntraBlockState&) {}

}