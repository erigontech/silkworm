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

#ifndef SILKWORM_CONSENSUS_CLIQUE_SNAPSHOT
#define SILKWORM_CONSENSUS_CLIQUE_SNAPSHOT

#include <map>
#include <silkworm/common/base.hpp>
#include <nlohmann/json.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/types/block.hpp>
#include <silkworm/consensus/validation.hpp>
#include <deque>

namespace silkworm {

extern std::array<uint8_t, 8> kNonceAuthorize;
extern std::array<uint8_t, 8> kNonceUnauthorize;

constexpr uint64_t kDiffInTurn = 2; // Block difficulty for in-turn signatures
constexpr uint64_t kDiffNoTurn = 1; // Block difficulty for out-of-turn signatures
// CliqueConfig is the consensus engine configs for proof-of-authority based sealing.
struct CliqueConfig {
	uint64_t   period; // Number of seconds between blocks to enforce
    uint64_t   epoch;  // Epoch length to reset votes and checkpoint
};

// Tally is a simple vote tally to keep the current score of votes. Votes that
// go against the proposal aren't counted since it's equivalent to not voting.
struct Tally {
	bool     authorize;                // Whether the vote is about authorizing or kicking someone
	uint64_t votes;                    // Number of votes until now wanting to pass the proposal
    std::vector<evmc::address> voters; // Voters for current proposal
};

// Voting Snapshot for Clique
class CliqueSnapshot {
    public:
        CliqueSnapshot() = default;
        CliqueSnapshot(uint64_t block_number, evmc::bytes32 hash, std::vector<evmc::address> signers,
                       std::deque<evmc::address> recents):
                        block_number_{block_number}, hash_{hash}, signers_{signers}, recents_{recents} {}

        //! \brief Updated snapshot by adding headers
        //! \param headers: list of headers to add.
        //! \param config: clique config.
        ValidationResult add_header(const BlockHeader& header, const evmc::address& signer, const CliqueConfig& config);
        //! \brief Verify seal for header
        //! \param header: header to verify.
        ValidationResult verify_seal(const BlockHeader& header, const evmc::address& signer);

        //! \brief Checks for authority
        //! \param block_number: Block to check.
        //! \param address: Address to check.
        //! \return if a signer at a given block height is in charge or not.
        bool is_authority(uint64_t block_number, evmc::address address) const noexcept;

        //! \brief Getter method for signers_.
        //! \return Snapshot's signers.
        const std::vector<evmc::address>& get_signers() const noexcept;

        //! \brief Getter method for recents_.
        //! \return Snapshot's recents.
        const std::deque<evmc::address>& get_recents() const noexcept;

        //! \brief Getter method for block_number_.
        //! \return Snapshot's block number.
        const uint64_t& get_block_number() const noexcept;

        //! \brief Getter method for hash_.
        //! \return Snapshot's hash.
        const evmc::bytes32& get_hash() const noexcept;
        //! \brief Convert the snapshot in Bytes.
        //! \return The resulting Bytes.
        Bytes to_bytes() const noexcept;
        //! \brief Decode snapshot from Bytes format.
        //! \return Decoded snapshot.
        static CliqueSnapshot from_bytes(ByteView& b, const uint64_t& block_number, const evmc::bytes32& hash) noexcept;

    private:
        // is_vote_valid returns whether it makes sense to cast the specified vote in the
        // given snapshot context (e.g. don't try to add an already authorized signer).
        bool is_vote_valid(const evmc::address& address, bool authorize) const noexcept;
        // increment_vote adds a new vote into the tally.
        void increment_vote(const evmc::address& address, const evmc::address& signer, bool authorize);
        // decrement_vote removes a previously cast vote from the tally.
        void decrement_vote(const evmc::address& address, const evmc::address& signer);
        // clear_votes removes every cast vote from the signer.
        void clear_votes(const evmc::address& signer);
        // update update snapshots and cleans it up from db corruption, etc..
        void update(const uint64_t& block_number, const evmc::bytes32& hash);

        uint64_t block_number_{0};                          // Block number where the snapshot was created
        evmc::bytes32 hash_;                                // Block hash where the snapshot was created
        std::vector<evmc::address> signers_;                // Set of authorized signers at this moment
        std::deque<evmc::address> recents_;                 // Set of recent signers for spam protections
        std::map<evmc::address, Tally> tallies_;            // Current vote tally to avoid recalculating
};

constexpr CliqueConfig kDefaultCliqueConfig = {
    15,
    30000,
}; // Ropsten and Görli configuration

}
#endif // SILKWORM_CONSENSUS_CLIQUE_SNAPSHOT