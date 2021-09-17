/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "clique_snapshot.hpp"
#include <silkworm/common/endian.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <cstring>

namespace silkworm {

std::array<uint8_t, 8> kNonceAuthorize =   {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
std::array<uint8_t, 8> kNonceUnauthorize = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

//! \brief Updated snapshot by adding headers
//! \param headers: list of headers to add.
ValidationResult CliqueSnapshot::add_header(const BlockHeader& header, const evmc::address& signer, const CliqueConfig& config) {
    auto hash{header.hash()};
    auto tmp_recents{recents_}; // We only modify snapshot after checks are done.
    // Delete the oldest signer from the recent list to allow it signing again
    if (recents_.size() > signers_.size() / 2) {
        tmp_recents.pop_back();
    }

    if (std::find(signers_.begin(), signers_.end(), signer) == signers_.end()) {
        return ValidationResult::kUnhauthorizedSigner;
    }

    // Remove any votes on checkpoint blocks
    if (header.number % config.epoch == 0) {
        tallies_.clear();
    }

    if (std::find(tmp_recents.begin(), tmp_recents.end(), signer) != tmp_recents.end()) {
        return ValidationResult::kRecentlySigned;
    }

    // We check what the vote is
    bool authorize;
    if (header.nonce == kNonceAuthorize) {
        authorize = true;
    } else if (header.nonce == kNonceUnauthorize) {
        authorize = false;
    } else {
        return ValidationResult::kInvalidVote;
    }
    
    tmp_recents.push_front(signer);
    recents_ = tmp_recents;

    if (!header.beneficiary) {
        update(header.number, hash);
        return ValidationResult::kOk;
    }

    // Uncast votes from signers
    decrement_vote(header.beneficiary, signer);
    // do casting
    increment_vote(header.beneficiary, signer, authorize);
    // If the vote passed, update the list of signers
    auto current_tally{tallies_[header.beneficiary]};
    if (current_tally.votes > signers_.size() / 2) {
        if (current_tally.authorize) {
            signers_.push_back(header.beneficiary);
        } else {
            signers_.erase(std::remove(signers_.begin(), signers_.end(), header.beneficiary), signers_.end());
            // Clean up recents
            recents_.pop_back();
            // Update Tallies
            clear_votes(header.beneficiary);
        }
        if (tallies_.count(header.beneficiary)) {
            tallies_.erase(header.beneficiary);
        }
    }

    update(header.number, hash);
    // Success
    return ValidationResult::kOk;
}

//! \brief Verify seal for header
//! \param header: header to verify.
ValidationResult CliqueSnapshot::verify_seal(const BlockHeader& header, const evmc::address& signer) {
    // Check difficituly
    auto authority{is_authority(header.number, signer)};
    if (authority && header.difficulty != kDiffInTurn && header.difficulty != kDiffNoTurn) {
        return ValidationResult::kIntrinsicGas;
    }

    return ValidationResult::kOk;
}

//! \brief Checks for authority
//! \param block_number: Block to check.
//! \param address: Address to check.
//! \return if a signer at a given block height is in charge or not.
bool CliqueSnapshot::is_authority(uint64_t block_number, evmc::address address) const noexcept {
    uint64_t offset{0};
	while (offset < signers_.size() && signers_[offset] != address) {
		++offset;
	}
	return (block_number % signers_.size()) == offset;
}

//! \brief Getter method for signers_.
//! \return Snapshot's signers.
const std::vector<evmc::address>& CliqueSnapshot::get_signers() const noexcept {
    return signers_;
}

//! \brief Getter method for block_number_.
//! \return Snapshot's block number.
const uint64_t& CliqueSnapshot::get_block_number() const noexcept {
    return block_number_;
}

//! \brief Getter method for hash_.
//! \return Snapshot's hash.
const evmc::bytes32& CliqueSnapshot::get_hash() const noexcept {
    return hash_;
}

//! \brief Convert the snapshot in Bytes.
//! \return The resulting Bytes.
Bytes CliqueSnapshot::to_bytes() const noexcept {
    auto signers_size{signers_.size()};
    auto recents_size{recents_.size()};
    Bytes ret(signers_size * kAddressLength + recents_size * kAddressLength + 1, '\0');
    // We specify how many are signers
    ret[0] = signers_.size();
    // We add the signers
    size_t i = 0;
    for (const auto &signer: signers_) {
        std::memcpy(&ret[i * kAddressLength + 1], signer.bytes, kAddressLength);
        i++;
    }
    // We add the recents
    i = 0;
    for (const auto &recent: recents_) {
        std::memcpy(&ret[signers_size * kAddressLength + i * kAddressLength + 1], recent.bytes, kAddressLength);
        i++;
    }
    return ret;
}

//! \brief Decode snapshot from bytes format.
//! \return Decoded snapshot.
CliqueSnapshot CliqueSnapshot::from_bytes(ByteView& b, uint64_t& block_number, const evmc::bytes32& hash) noexcept {
    auto signers_count{b[0]};
    auto recents_count{(b.size() - signers_count * kAddressLength - 1) / kAddressLength};
    // Add Signers
    std::vector<evmc::address> signers;
    for (size_t i = 0; i < signers_count; i++) {
        evmc::address signer;
        std::memcpy(signer.bytes, &b[i * kAddressLength + 1], kAddressLength);
        signers.push_back(signer);
    }
    // Add Recents
    std::deque<evmc::address> recents;
    for (size_t i = 0; i < recents_count; i++) {
        evmc::address signer;
        std::memcpy(signer.bytes, &b[signers_count * kAddressLength + i * kAddressLength + 1], kAddressLength);
        recents.push_back(signer);
    }
    // Make sure signers are sorted before turn-ness check
    std::sort(signers.begin(), signers.end());
    return CliqueSnapshot{block_number, hash, signers, recents};
}

bool CliqueSnapshot::is_vote_valid(const evmc::address& address, bool authorize) const noexcept {
    auto existing_signer{std::find(signers_.begin(), signers_.end(), address) != signers_.end()};
    return (existing_signer && !authorize) || (!existing_signer && authorize);
}
// cast a vote made to address by signer
void CliqueSnapshot::increment_vote(const evmc::address& address, const evmc::address& signer, bool authorize) {
    if (!is_vote_valid(address, authorize)) {
        return;
    }
    auto tally{tallies_.find(address)};
    if (tally != tallies_.end()) {
        // Update existing tally
        tallies_[address].votes += 1;
        tallies_[address].voters.push_back(signer);
    } else {
        // Create new tally
        tallies_.emplace(address, Tally{authorize, 1, {signer}});
    }
}
// uncast the vote made to address by signer
void CliqueSnapshot::decrement_vote(const evmc::address& address, const evmc::address& signer) {
    if(tallies_.count(address)) {
        if (std::find(tallies_[address].voters.begin(), 
            tallies_[address].voters.end(), signer) == tallies_[address].voters.end()) {
            return;
        }
        if (tallies_[address].votes <= 1) {
            tallies_.erase(address);
        } else {
            tallies_[address].votes--;
            std::remove(tallies_[address].voters.begin(), tallies_[address].voters.end(), signer);
        }
    }
}
// Uncast all of the votes made by signer
void CliqueSnapshot::clear_votes(const evmc::address& signer) {
    for (auto& [address, tally]: tallies_) {
        auto vote{std::find(tally.voters.begin(), tally.voters.end(), signer)};
        if (vote != tally.voters.end() && tally.votes > 0) {
            tally.votes--;
            tally.voters.erase(vote);
        }
    }
    // Clean up for whenever votes was equal to 0
    auto it{tallies_.begin()};
    while(it != tallies_.end()) {
        if (it->second.votes == 0) {
            auto to_erase{it};
            it++;
            tallies_.erase(to_erase);
        } else {
            it++;
        } 
    }
}

void CliqueSnapshot::update(const uint64_t& block_number, const evmc::bytes32& hash) {
    block_number_ = block_number;
    std::memcpy(hash_.bytes, hash.bytes, kHashLength);
    // Sort signers for turness + Cleanup
    std::sort(signers_.begin(), signers_.end());
    signers_.erase(std::unique(signers_.begin(), signers_.end()), signers_.end());
}

}  // namespace silkworm
