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
#include <silkworm/crypto/ecdsa.hpp>
#include <cstring>

namespace silkworm {

std::array<uint8_t, 8> kNonceAuthorize =   {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
std::array<uint8_t, 8> kNonceUnauthorize = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

evmc::address get_signer_from_clique_header(BlockHeader header) { // taking the header not by reference is intentional
    Bytes ecrecover_data(kHashLength + kSignatureLength, '\0');
    // Insert signature first
    auto signature{header.extra_data.substr(header.extra_data.size() - kSignatureLength)};
    std::memcpy(&ecrecover_data[kHashLength], 
                &signature[0], 
                kSignatureLength);
    // Generate Sealing Hash for Clique
    // for_sealing = false, with signature in extra_data
    header.extra_data = signature; // we modify header directly, that is why we do not make copies
    auto header_hash{header.hash()};
    // Run Ecrecover and get public key
    auto pub_key{*ecdsa::recover(full_view(header_hash), signature.substr(0, kSignatureLength - 1), signature[kSignatureLength - 1])};
    // Convert public key to address
    evmc::address signer;
    std::memcpy(signer.bytes, &pub_key[12], kAddressLength);

    return signer;
}

//! \brief Updated snapshot by adding headers
//! \param headers: list of headers to add.
ValidationResult CliqueSnapshot::add_headers(std::vector<BlockHeader> headers, CliqueConfig config) {
	// Sanity check that the headers can be applied
	for (size_t i = 0; i < headers.size() - 1; ++i) {
		if (headers[i+1].number != headers[i].number +1) {
			return ValidationResult::kInvalidVotingSegment;
		}
	}

	if (headers[0].number != block_number_ + 1) {
		return ValidationResult::kInvalidVotingSegment;
	}

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
        if (std::find(signers_.begin(), signers_.end(), signer) == signers_.end()) {
            return ValidationResult::kUnhauthorizedSigner;
        }

        for(const auto& [_, recent]: recents_) {
            if (signer == recent) {
                return ValidationResult::kRecentlySigned;
            }
        }
        recents_[header.number] = signer;

        for(auto it = votes_.begin(); it != votes_.end(); it++)  {
            auto vote{*it};
            if (vote.signer == signer && vote.address == header.beneficiary) {
				// Uncast the vote from the cached tally
				uncast(vote.address, vote.authorize);

				// Uncast the vote from the chronological list
				votes_.erase(votes_.begin(), it + 1);
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

//! \brief Convert the snapshot in JSON.
//! \return The resulting JSON.
nlohmann::json CliqueSnapshot::to_json() const noexcept {
    nlohmann::json ret; // Returning json
    // Block Number and Hash
    ret["number"] = block_number_;
    ret["hash"]   = to_hex(hash_);
    // Signers
    for (const auto& address: signers_) {
        ret["signers"][to_hex(address)] = nullptr;
    }
    // Recents
    for (const auto& [block_number, address]: recents_) {
        Bytes block_number_bytes(4, '\0');
        endian::store_big_u32(&block_number_bytes[0], block_number);
        ret["recents"][to_hex(block_number_bytes).insert(0, "0x")] = to_hex(address);
    }
    
    // Votes
    ret["votes"] = nlohmann::json::array();
    nlohmann::json vote_json;
    // Iterates over each vote
    for (const auto& vote: votes_) {
        // Build a vote JSON
        vote_json["signer"]    = to_hex(vote.signer);
        vote_json["address"]   = to_hex(vote.address);
        vote_json["block"]     = vote.block_number;
        vote_json["authorize"] = vote.authorize;
        // Push it to the votes array
        ret["votes"].push_back(vote_json);
    }
    // Tallies
    for (const auto& [address, tally]: tallies_) {
        ret["tally"][to_hex(address)]["authorize"] = tally.authorize;
        ret["tally"][to_hex(address)]["votes"]     = tally.votes;
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
    absl::btree_map<uint64_t, evmc::address> recents;
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
    absl::btree_map<evmc::address, Tally> tallies;
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
        ++tallies_[address].votes;
    } else {
        // Create new tally
        tallies_[address] = {authorize, 1};
    }

    return true;
}

void CliqueSnapshot::uncast(evmc::address address, bool authorize) {
    // If there's no tally, it's a dangling vote, just drop
    if (tallies_.find(address) != tallies_.end()) {
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
