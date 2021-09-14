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
ValidationResult CliqueSnapshot::add_header(BlockHeader header) {
    // Delete the oldest signer from the recent list to allow it signing again
    if (recents_.size() > 0) {
        recents_.pop_back();
    }

    auto signer{get_signer_from_clique_header(header)};
    if (signer == std::nullopt) {
        return ValidationResult::kUnhauthorizedSigner;
    }
    if (std::find(signers_.begin(), signers_.end(), *signer) == signers_.end()) {
        return ValidationResult::kUnhauthorizedSigner;
    }

    if (std::find(recents_.begin(), recents_.end(), signer) != recents_.end()) {
        return ValidationResult::kRecentlySigned;
    }

    recents_.push_front(*signer);

    // Remove any votes on checkpoint blocks
    if (header.beneficiary == 0x0000000000000000000000000000000000000000_address) {
        tallies_.clear();
        return ValidationResult::kOk;
    }
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
            signers_.push_back(header.beneficiary);
        } else {
            std::remove(signers_.begin(), signers_.end(), header.beneficiary);
            // Clean up recents
            if (recents_.size() > 0) {
                recents_.pop_back();
            }
            // Update Tallies
            uncast(header.beneficiary);
            // filtered out signers votes
            votes_.erase(header.beneficiary);
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
nlohmann::json CliqueSnapshot::to_json() const noexcept {
    nlohmann::json ret; // Returning json
    nlohmann::json empty_object(nlohmann::json::value_t::object);
    // Block Number and Hash
    ret.emplace("number", block_number_);
    ret.emplace("hash", to_hex(hash_));
    // Signers
    if (signers_.size() > 0) {
        for (const auto& address: signers_) {
            ret["signers"].emplace(to_hex(address), empty_object);
        }
    } else {
        ret.emplace("signers", empty_object);
    }
    if (recents_.size() > 0) {
        // Recents
        for (const auto& address: recents_) {
            ret["recents"].push_back(to_hex(address));
        }
    } else {
        ret.emplace("recents", nlohmann::json::value_t::array);
    }

    if (votes_.size() > 0) {
        // Iterates over each vote
        for (const auto& [signer, address]: votes_) {
            // Build a vote JSON
            ret["votes"].emplace(to_hex(signer), to_hex(address));
        }
    } else {
        ret.emplace("votes", empty_object);
    }

    // Tallies
    if (tallies_.size() > 0) {
        for (const auto& [address, tally]: tallies_) {
            ret["tally"][to_hex(address)]["authorize"] = tally.authorize;
            ret["tally"][to_hex(address)]["votes"]     = tally.votes;
        }
    } else {
        ret.emplace("tally", empty_object);
    }

    if (ret.is_array()) { // on linux it becomes an array for some reason. this is a temporary solution
        return ret[0];
    }
    return ret;
}

//! \brief Decode snapshot from json format.
//! \return Decoded snapshot.
CliqueSnapshot CliqueSnapshot::from_json(const nlohmann::json& json) noexcept {
    // Block Number
    uint64_t block_number{json["number"].get<uint64_t>()};
    
    // Hash
    evmc::bytes32 hash;
    std::memcpy(hash.bytes, from_hex(json["hash"].get<std::string>())->c_str(), kHashLength);
    // Assign signers
    std::vector<evmc::address> signers;
    for (auto it = json["signers"].begin(); it != json["signers"].end(); ++it) {
        evmc::address signer;
        std::memcpy(signer.bytes, from_hex(it.key())->c_str(), kAddressLength);
        signers.push_back(signer);
    }
    // Assign recents
    std::deque<evmc::address> recents;
    for (auto it = json["recents"].begin(); it != json["recents"].end(); ++it) {
        // We compute address (JSON value)
        evmc::address address;
        std::memcpy(address.bytes, from_hex(it->get<std::string>())->c_str(), kAddressLength);
        recents.push_back(address);
    }
    // Assign votes
    std::map<evmc::address, evmc::address> votes;
    for (auto it = json["votes"].begin(); it != json["votes"].end(); ++it) {
        evmc::address signer{};
        evmc::address address{};
        std::memcpy(signer.bytes, from_hex(it.key())->c_str(), kAddressLength);
        std::memcpy(address.bytes, from_hex(it->get<std::string>())->c_str(), kAddressLength);
        votes[signer] = address;
    }

    // Assign tallies
    std::map<evmc::address, Tally> tallies;
    for (auto it = json["tally"].begin(); it != json["tally"].end(); ++it) {
        Tally t;
        evmc::address address;
        std::memcpy(address.bytes, from_hex(it.key())->c_str(), kAddressLength);
        t.votes =      it.value()["votes"].get<uint64_t>();
        t.authorize =  it.value()["authorize"].get<bool>();
        tallies[address] = t;
    }
    // Make sure signers are sorted before turn-ness check
    std::sort(signers.begin(), signers.end());
    return CliqueSnapshot{block_number, hash, signers, recents, tallies, votes};
}

bool CliqueSnapshot::is_vote_valid(evmc::address address, bool authorize) const noexcept {
    auto existing_signer{std::find(signers_.begin(), signers_.end(), address) != signers_.end()};
    return (existing_signer && !authorize) || (!existing_signer && authorize);
}

bool CliqueSnapshot::cast(evmc::address address, bool authorize) {
    if (!is_vote_valid(address, authorize)) {
        return false;
    }
    if (tallies_.find(address) != tallies_.end()) {
        // Update existing tally
        tallies_[address].votes += 1;
    } else {
        // Create new tally
        tallies_.emplace(address, Tally{authorize, 1});
    }

    return true;
}

void CliqueSnapshot::uncast(evmc::address address) {
    auto previous_vote{votes_.find(address)};
    if (previous_vote != votes_.end()) {
        auto address_voted{previous_vote->second};
        if (tallies_[address_voted].votes == 1) {
            tallies_.erase(address_voted);
        } else {
            tallies_[address_voted].votes--;
        }
    }
}

}  // namespace silkworm
