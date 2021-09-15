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
#include <iostream>

namespace silkworm {

std::array<uint8_t, 8> kNonceAuthorize =   {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
std::array<uint8_t, 8> kNonceUnauthorize = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// taking the header not by reference is intentional
std::optional<evmc::address> get_signer_from_clique_header(BlockHeader header) {
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
    if (recovered == std::nullopt) {
        return std::nullopt;
    }
    auto hash{keccak256(recovered->substr(1))};
    // Convert public key to address
    evmc::address signer{};
    std::memcpy(signer.bytes, &hash.bytes[12], kAddressLength);
    return signer;
}

//! \brief Updated snapshot by adding headers
//! \param headers: list of headers to add.
ValidationResult CliqueSnapshot::add_header(BlockHeader header, CliqueConfig config) {
    // Remove any votes on checkpoint blocks
    if (header.number % config.epoch == 0) {
        tallies_.clear();
        votes_.clear();
    }
    // Delete the oldest signer from the recent list to allow it signing again
    if (recents_.size() > 0) {
        recents_.pop_back();
    }

    auto signer{get_signer_from_clique_header(header)};
    if (signer == std::nullopt) {
        return ValidationResult::kUnhauthorizedSigner;
    }
    if (std::find(signers_.begin(), signers_.end(), *signer) == signers_.end()) {
        std::cout << to_hex(*signer) << " was unhauthorized" << std::endl;
        return ValidationResult::kUnhauthorizedSigner;
    }

    if (std::find(recents_.begin(), recents_.end(), signer) != recents_.end()) {
        return ValidationResult::kRecentlySigned;
    }

    recents_.push_front(*signer);

    // Uncast votes from signers
    uncast(*signer);
    // We check what the vote is
    bool authorize;
    if (header.nonce == kNonceAuthorize) {
        authorize = true;
    } else if (header.nonce == kNonceUnauthorize) {
        authorize = false;
    } else {
        return ValidationResult::kInvalidVote;
    }

    if (cast(header.beneficiary, authorize)) {
        votes_[*signer] = header.beneficiary;
    }

    // If the vote passed, update the list of signers
    auto current_tally{tallies_[header.beneficiary]};
    if (current_tally.votes > signers_.size() / 2) {
        if (current_tally.authorize) {
            std::cout << "Signer " << to_hex(*signer) << ", Added: " << to_hex(header.beneficiary)
                      << " at block: " << header.number << std::endl;
            signers_.push_back(header.beneficiary);
        } else {
            std::cout << "Signer " << to_hex(*signer) << ", Removed: " << to_hex(header.beneficiary) 
                    << " at block: " << header.number << std::endl;
            std::remove(signers_.begin(), signers_.end(), header.beneficiary);
            // Clean up recents
            if (recents_.size() > 0) {
                recents_.pop_back();
            }
            // Update Tallies
            uncast(header.beneficiary);
        }   
        // Clean up votes
        auto it{votes_.begin()};
        while (it != votes_.end()) {
            if (it->second == header.beneficiary) {
                it = votes_.erase(it);
            } else {
                it++;
            }
        }
        
        tallies_.erase(header.beneficiary);
    }
    block_number_ = header.number;
    std::memcpy(hash_.bytes, header.hash().bytes, kHashLength);
    // Sort signers for turness
    std::sort(signers_.begin(), signers_.end());

    // Success
    return ValidationResult::kOk;
}

//! \brief Verify seal for header
//! \param header: header to verify.
ValidationResult CliqueSnapshot::verify_seal(BlockHeader header) {
    auto signer{get_signer_from_clique_header(header)};

    if (signer == std::nullopt) {
        return ValidationResult::kInvalidVotingSegment;
    }

    // Check difficituly
    auto authority{is_authority(header.number, *signer)};
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

//! \brief Convert the snapshot in JSON.
//! \return The resulting JSON.
Bytes CliqueSnapshot::to_bytes() const noexcept {
    Bytes ret(signers_.size() * kAddressLength, '\0');
    size_t i = 0;
    for (const auto &signer: signers_) {
        std::memcpy(&ret[i * kAddressLength], signer.bytes, kAddressLength);
        i++;
    }
    return ret;
}

//! \brief Decode snapshot from json format.
//! \return Decoded snapshot.
CliqueSnapshot CliqueSnapshot::from_bytes(ByteView& b, uint64_t& block_number, const evmc::bytes32& hash) noexcept {
    auto signers_count{b.size() / kAddressLength};
    std::vector<evmc::address> signers;
    for (size_t i = 0; i < signers_count; i++) {
        evmc::address signer;
        std::memcpy(signer.bytes, &b[i * kAddressLength], kAddressLength);
        signers.push_back(signer);
    }
    // Make sure signers are sorted before turn-ness check
    std::sort(signers.begin(), signers.end());
    return CliqueSnapshot{block_number, hash, signers};
}

bool CliqueSnapshot::is_vote_valid(evmc::address address, bool authorize) const noexcept {
    auto existing_signer{std::find(signers_.begin(), signers_.end(), address) != signers_.end()};
    return (existing_signer && !authorize) || (!existing_signer && authorize);
}

bool CliqueSnapshot::cast(evmc::address address, bool authorize) {
    if (!is_vote_valid(address, authorize)) {

        std::cout << authorize << std::endl;
            std::cout << "detected invalid cast" << std::endl;
        return false;
    }
    auto tally{tallies_.find(address)};
    if (tally != tallies_.end()) {
        // Update existing tally
        tallies_[address].votes += 1;
        std::cout << "casted vote " << tallies_[address].votes << " on " << to_hex(address) << std::endl;
    } else {
        // Create new tally
        tallies_.emplace(address, Tally{authorize, 1});
        std::cout << "create tally with vote " << authorize << " on " << to_hex(address) << std::endl;
    }

    return true;
}

void CliqueSnapshot::uncast(evmc::address address) {
    auto previous_vote{votes_.find(address)};
    if (previous_vote != votes_.end()) {
        auto address_voted{previous_vote->second};
        if (tallies_[address_voted].votes <= 1) {
            tallies_.erase(address_voted);
            std::cout << "erased tally for " << to_hex(address_voted) << std::endl;
        } else {
            tallies_[address_voted].votes--;
            std::cout << "erased tally for " << to_hex(address_voted) << " to " << tallies_[address_voted].votes << std::endl;
        }
        votes_.erase(previous_vote);
    } else {
        std::cout << "detected invalid uncast " << to_hex(address) << std::endl;
    }

}

}  // namespace silkworm
