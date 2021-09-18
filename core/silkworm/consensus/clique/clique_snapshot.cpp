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

#include <cstring>

#include <silkworm/common/endian.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/crypto/ecdsa.hpp>

namespace silkworm {

std::array<uint8_t, 8> kNonceAuthVote = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
std::array<uint8_t, 8> kNonceDropVote = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

//! \brief Updated snapshot by adding headers
//! \param headers: list of headers to add.
ValidationResult CliqueSnapshot::add_header(const BlockHeader& header, const evmc::address& signer,
                                            const CliqueConfig& config) {
    // Block 0 is unsupported
    auto hash{header.hash()};
    if (header.number == 0) {
        update(header.number, hash);
        return ValidationResult::kOk;
    }

    if (std::find(signers_.begin(), signers_.end(), signer) == signers_.end()) {
        return ValidationResult::kUnauthorizedSigner;
    }

    // Remove any votes on checkpoint blocks
    if (header.number % config.epoch == 0) {
        tallies_.clear();
    }

    // We need to determine if this signer is allowed to vote.
    // Conditions are either :
    // 1 - The signer has not recently voted
    // 2 - The signer has recently voted BUT is the least recent AND the queue would be popped
    auto pop_least_recent{static_cast<int64_t>(recents_.size() > signers_.size() / 2)};
    if (std::find(recents_.begin(), std::prev(recents_.end(), pop_least_recent), signer) != recents_.end()) {
        return ValidationResult::kRecentlySigned;
    }

    // We check what the vote is
    bool authorize;
    if (header.nonce == kNonceAuthVote) {
        authorize = true;
    } else if (header.nonce == kNonceDropVote) {
        authorize = false;
    } else {
        return ValidationResult::kInvalidVote;
    }

    if (pop_least_recent) {
        recents_.pop_back();
    }
    recents_.push_front(signer);

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
    // Check difficulty
    if (is_authority(header.number, signer) && header.difficulty != kDiffInTurn && header.difficulty != kDiffNoTurn) {
        return ValidationResult::kInvalidSeal;
    }

    return ValidationResult::kOk;
}

//! \brief Checks for authority
//! \param block_number: Block to check.
//! \param address: Address to check.
//! \return if a signer at a given block height is in charge or not.
bool CliqueSnapshot::is_authority(uint64_t block_number, evmc::address address) const noexcept {
    if (signers_.empty()) {
        return false;
    }
    return signers_[block_number % signers_.size()] == address;
}

//! \brief Getter method for signers_.
//! \return Snapshot's signers.
const std::vector<evmc::address>& CliqueSnapshot::get_signers() const noexcept { return signers_; }
//! \brief Getter method for recents_.
//! \return Snapshot's recents.
const std::deque<evmc::address>& CliqueSnapshot::get_recents() const noexcept { return recents_; }

//! \brief Getter method for block_number_.
//! \return Snapshot's block number.
const uint64_t& CliqueSnapshot::get_block_number() const noexcept { return block_number_; }

//! \brief Getter method for hash_.
//! \return Snapshot's hash.
const evmc::bytes32& CliqueSnapshot::get_hash() const noexcept { return hash_; }

//! \brief Convert the snapshot in Bytes.
//! \return The resulting Bytes.
Bytes CliqueSnapshot::to_bytes() const noexcept {
    auto signers_bytes_count{signers_.size() * kAddressLength};
    auto recents_bytes_count{recents_.size() * kAddressLength};
    Bytes ret(signers_bytes_count + recents_bytes_count + 8 /* byte for signers count*/, '\0');

    // We specify how many are signers
    size_t offset{0};
    endian::store_big_u64(&ret[offset], signers_.size());
    offset += sizeof(uint64_t);
    std::memcpy(&ret[offset], signers_.data(), signers_bytes_count);
    offset += signers_bytes_count;

    // We add the recents
    for (const auto& recent : recents_) {
        std::memcpy(&ret[offset], recent.bytes, kAddressLength);
        offset += kAddressLength;
    }

    return ret;
}

//! \brief Decode snapshot from bytes format.
//! \return Decoded snapshot.
CliqueSnapshot CliqueSnapshot::from_bytes(ByteView& b, const uint64_t& block_number,
                                          const evmc::bytes32& hash) noexcept {
    // Consume signers count
    auto signers_count{endian::load_big_u64(&b[0])};
    auto signers_bytes_count{signers_count * kAddressLength};
    b.remove_prefix(sizeof(uint64_t));

    // Consume signers
    std::vector<evmc::address> signers(signers_count);
    memcpy(&signers[0], b.data(), signers_bytes_count);
    b.remove_prefix(signers_bytes_count);

    // Consume recents
    std::deque<evmc::address> recents;
    while (!b.empty()) {
        evmc::address signer;
        std::memcpy(signer.bytes, b.data(), kAddressLength);
        recents.push_back(signer);
        b.remove_prefix(kAddressLength);
    }

    // Make sure signers are sorted before turn-ness check
    std::sort(signers.begin(), signers.end());
    return CliqueSnapshot{block_number, hash, signers, recents};
}

bool CliqueSnapshot::is_vote_valid(const evmc::address& address, bool authorize) const noexcept {
    auto existing_signer{std::find(signers_.begin(), signers_.end(), address) != signers_.end()};
    return (existing_signer && !authorize) || (!existing_signer && authorize);
}
// increment_vote a vote made to address by signer
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
// decrement_vote the vote made to address by signer
void CliqueSnapshot::decrement_vote(const evmc::address& address, const evmc::address& signer) {
    if (tallies_.count(address)) {
        if (std::find(tallies_[address].voters.begin(), tallies_[address].voters.end(), signer) ==
            tallies_[address].voters.end()) {
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
// clear_votes all of the votes made by signer
void CliqueSnapshot::clear_votes(const evmc::address& signer) {
    for (auto& [address, tally] : tallies_) {
        auto vote{std::find(tally.voters.begin(), tally.voters.end(), signer)};
        if (vote != tally.voters.end() && tally.votes > 0) {
            tally.votes--;
            tally.voters.erase(vote);
        }
    }
    // Clean up for whenever votes was equal to 0
    auto it{tallies_.begin()};
    while (it != tallies_.end()) {
        if (it->second.votes == 0) {
            it = tallies_.erase(it);
            continue;
        }
        it++;
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
