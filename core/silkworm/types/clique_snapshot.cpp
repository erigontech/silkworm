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
    std::cout << "a " << to_hex(signer) << std::endl;
    return signer;
}

//! \brief Updated snapshot by adding headers
//! \param headers: list of headers to add.
ValidationResult CliqueSnapshot::add_headers(std::vector<BlockHeader> headers, CliqueConfig config) {
    // make sure headers are sorted per block number
    std::sort(headers.begin(), headers.end(),[](
            BlockHeader& a, 
            BlockHeader& b) { 
        return a.number < b.number;
    });
    for(const auto& header: headers) {
        // Remove any votes on checkpoint blocks
        if (header.number % config.epoch == 0) {
            votes_.clear();
            tallies_.clear();
        }
		// Delete the oldest signer from the recent list to allow it signing again
        uint64_t limit{(signers_.size() / 2) + 1};

		if  (header.number >= limit) {
			recents_.erase(header.number - limit);
		}
        auto signer{get_signer_from_clique_header(header)};
        if (signer == std::nullopt) {
            return ValidationResult::kUnhauthorizedSigner;
        }
        std::cout << "b " << to_hex(header.beneficiary) << std::endl;
        std::cout << "c " << to_hex(*signer) << std::endl;
        std::cout << block_number_ << std::endl;
        if (std::find(signers_.begin(), signers_.end(), *signer) == signers_.end()) {
            return ValidationResult::kUnhauthorizedSigner;
        }

        for(const auto& [_, recent]: recents_) {
            if (signer == recent) {
                return ValidationResult::kRecentlySigned;
            }
        }
        recents_[header.number] = *signer;

        for(auto it = votes_.begin(); it != votes_.end(); it++)  {
            auto vote{*it};
            if (vote.signer == signer && vote.address == header.beneficiary) {
				// Uncast the vote from the cached tally
				uncast(vote.address, vote.authorize);

				// Uncast the vote from the chronological list
				votes_.erase(it);
				break; // only one vote allowed
            }
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
        if (cast(header.beneficiary, authorize)) {
            votes_.push_back({*signer, header.beneficiary, header.number, authorize});
        
            // If the vote passed, update the list of signers
            auto current_tally{tallies_[header.beneficiary]};
            if (current_tally.votes > signers_.size() / 2) {
                if (current_tally.authorize) {
                    signers_.push_back(header.beneficiary);
                } else {
                    std::remove(signers_.begin(), signers_.end(), header.beneficiary);
                    // Update limit and clean up snapshot
                    limit = (signers_.size() / 2) + 1;
                    if  (header.number >= limit) {
                        recents_.erase(header.number - limit);
                    }
                    // Update Tallies
                    for(auto it = votes_.begin(); it != votes_.end(); it++)  {
                        auto vote{*it};
                        if (vote.signer == header.beneficiary) {
                            uncast(vote.address, vote.authorize);
                        }
                    }
                    // Filter out
                    std::vector<Vote> filtered_votes;
                    std::copy_if (filtered_votes.begin(),
                                    filtered_votes.end(),
                                    std::back_inserter(filtered_votes), 
                                    [&header](Vote v){ return v.signer != header.beneficiary; }
                    );
                    votes_ = filtered_votes;
                }
                // Discard previous votes.
                for(auto it = votes_.begin(); it != votes_.end(); it++)  {
                    auto vote{*it};
                    if (vote.signer == header.beneficiary) {
                        votes_.erase(it);
                        it--;
                    }
                }
                tallies_.erase(header.beneficiary);
            }
        }
    }
    block_number_ = headers.back().number;
    std::memcpy(hash_.bytes, headers.back().hash().bytes, kHashLength);
    // Sort signers for turness
    std::sort(signers_.begin(), signers_.end(), [](
            evmc::address& a, 
            evmc::address& b) { 
        return std::strcmp(
            reinterpret_cast<char *>(a.bytes),
            reinterpret_cast<char *>(b.bytes)) < 0; 
    });

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
    if (std::find(signers_.begin(), signers_.end(), signer) == signers_.end()) {
        return ValidationResult::kUnhauthorizedSigner;
    }

    for (const auto& [block_number, address]: recents_) {
        if (address == signer && block_number > block_number_ - ((signers_.size() / 2) - 1)) {
            return ValidationResult::kRecentlySigned;
        }
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
        for (const auto& [block_number, address]: recents_) {
            Bytes block_number_bytes(4, '\0');
            endian::store_big_u32(&block_number_bytes[0], block_number);
            ret["recents"][to_hex(block_number_bytes).insert(0, "0x")] = to_hex(address);
        }
    } else {
        ret.emplace("recents", empty_object);
    }

    if (votes_.size() > 0) {
        // Iterates over each vote
        for (const auto& vote: votes_) {
            nlohmann::json vote_json;
            // Build a vote JSON
            vote_json.emplace("signer", to_hex(vote.signer));
            vote_json.emplace("address", to_hex(vote.address));
            vote_json.emplace("block", vote.block_number);
            vote_json.emplace("authorize", vote.authorize);
            // Push it to the votes array
            ret["votes"].push_back(vote_json);
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
    std::map<uint64_t, evmc::address> recents;
    for (auto it = json["recents"].begin(); it != json["recents"].end(); ++it) {
        // We compute address (JSON value)
        evmc::address address;
        std::memcpy(address.bytes, from_hex(it.value().get<std::string>())->c_str(), kAddressLength);
        // Block Number => Address
        recents[std::strtoull(it.key().c_str(), nullptr, 16)] = address;
    }
    // Assign votes
    std::vector<Vote> votes;
    for (auto it = json["votes"].begin(); it != json["votes"].end(); ++it) {
        Vote v;
        std::memcpy(v.signer.bytes, from_hex((*it)["signer"].get<std::string>())->c_str(), kAddressLength);
        std::memcpy(v.address.bytes, from_hex((*it)["address"].get<std::string>())->c_str(), kAddressLength);
        v.block_number = (*it)["block"].get<uint64_t>();
        v.authorize  = (*it)["authorize"].get<bool>();
        votes.push_back(v);
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
    std::sort(signers.begin(), signers.end(), [](
            evmc::address& a, 
            evmc::address& b) { 
        return std::strcmp(
            reinterpret_cast<char *>(a.bytes),
            reinterpret_cast<char *>(b.bytes)) < 0; 
    });
    return CliqueSnapshot{block_number, hash, signers, recents, votes, tallies};
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

void CliqueSnapshot::uncast(evmc::address address, bool authorize) {
    // If there's no tally, it's a dangling vote, just drop
    if (tallies_.find(address) == tallies_.end()) {
        return;
    }
    // Ensure we only revert counted votes
    if (tallies_[address].authorize != authorize) {
        return;
    }
	// Otherwise revert the vote
	if (tallies_[address].votes > 1) {
		--tallies_[address].votes;
	} else {
        // Tallies are empty now so we can just free them
		tallies_.erase(address);
	}
}

}  // namespace silkworm
