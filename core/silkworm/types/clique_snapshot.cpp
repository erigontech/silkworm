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
#include <silkworm/common/util.hpp>

namespace silkworm {

nlohmann::json CliqueSnapshot::to_json() const noexcept {
    nlohmann::json ret; // Returning json
    // Block Number and Hash
    ret["number"] = block_number_;
    ret["hash"]   = to_hex(hash_);
    // Signers
    for (const auto& address: signers_) {
        ret["signers"][to_hex(address)] = {};
    }
    // Recents
    for (const auto& [block_number, address]: recents_) {
        ret["recents"][block_number] = to_hex(address);
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
        ret["tallies"][to_hex(address)]["authorize"] = tally.authorize;
        ret["tallies"][to_hex(address)]["votes"]     = tally.votes;
    }

    return ret;
}

}  // namespace silkworm
