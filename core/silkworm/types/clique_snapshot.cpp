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

namespace silkworm {
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
std::optional<CliqueSnapshot> CliqueSnapshot::from_json(const nlohmann::json& json) noexcept {
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
    return CliqueSnapshot{block_number, hash, signers, recents, votes, tallies};
}

bool CliqueSnapshot::is_vote_valid(evmc::address signer, bool authorize) const noexcept {
    auto existing_signer{std::find(signers_.begin(), signers_.end(), signer) != signers_.end()};
    return (existing_signer && !authorize) || (!existing_signer && authorize);
}

}  // namespace silkworm
