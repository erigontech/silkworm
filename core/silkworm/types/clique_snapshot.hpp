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

#ifndef SILKWORM_TYPES_CLIQUE_SNAPSHOT
#define SILKWORM_TYPES_CLIQUE_SNAPSHOT

#include <absl/container/btree_map.h>
#include <silkworm/common/base.hpp>
#include <nlohmann/json.hpp>
#include <silkworm/common/util.hpp>

namespace silkworm {

// CliqueConfig is the consensus engine configs for proof-of-authority based sealing.
struct CliqueConfig {
	uint64_t   period; // Number of seconds between blocks to enforce
    uint64_t   epoch;  // Epoch length to reset votes and checkpoint
};

struct SnapshotConfig {
    uint64_t checkpoint_interval; // Number of blocks after which to save the vote snapshot to the database
    uint64_t inmemory_snapshots;  // Number of recent vote snapshots to keep in memory
	uint64_t inmemory_signatures; // Number of recent block signatures to keep in memory
};

// Vote represents a single vote that an authorized signer made to modify the
// list of authorizations.
struct Vote {
	evmc::address  signer;       // Authorized signer that cast this vote
	evmc::address  address;      // Account being voted on to change its authorization
	uint64_t       block_number; // Block number the vote was cast in (expire old votes)
	bool           authorize;    // Whether to authorize or deauthorize the voted account
};

// Tally is a simple vote tally to keep the current score of votes. Votes that
// go against the proposal aren't counted since it's equivalent to not voting.
struct Tally {
	bool     authorize; // Whether the vote is about authorizing or kicking someone
	uint64_t votes;     // Number of votes until now wanting to pass the proposal
};

// Voting Snapshot for Clique
class CliqueSnapshot {
    public:
        CliqueSnapshot() = default;
        CliqueSnapshot(uint64_t block_number, evmc::bytes32 hash, std::vector<evmc::address> signers,
                       absl::btree_map<uint64_t, evmc::address> recents, std::vector<Vote> votes,
                       absl::btree_map<evmc::address, Tally> tallies): 
                            block_number_{block_number}, hash_{hash}, signers_{signers},
                            recents_{recents}, votes_{votes}, tallies_{tallies} {}

        //! \brief Convert the snapshot in JSON.
        //! \return The resulting JSON.
        nlohmann::json to_json() const noexcept;
        //! \brief Decode snapshot from json format.
        //! \return Decoded snapshot.
        static std::optional<CliqueSnapshot> from_json(const nlohmann::json& json) noexcept;
    private:
        // validVote returns whether it makes sense to cast the specified vote in the
        // given snapshot context (e.g. don't try to add an already authorized signer).
        bool is_vote_valid(evmc::address signer, bool authorize) const noexcept;

        uint64_t block_number_;                            // Block number where the snapshot was created
        evmc::bytes32 hash_;                               // Block hash where the snapshot was created     
        std::vector<evmc::address> signers_;               // Set of authorized signers at this moment
        absl::btree_map<uint64_t, evmc::address> recents_; // Set of recent signers for spam protections
        std::vector<Vote> votes_;                          // List of votes cast in chronological order
        absl::btree_map<evmc::address, Tally> tallies_;    // Current vote tally to avoid recalculating
};

constexpr CliqueConfig kDefaultCliqueConfig = {
    15,
    30000,
}; // Ropsten and Görli configuration

constexpr SnapshotConfig kDefaultSnapshotConfig = {
    10,
    1024,
    16384
};

}
#endif // SILKWORM_TYPES_CLIQUE_SNAPSHOT