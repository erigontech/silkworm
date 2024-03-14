/*
   Copyright 2022 The Silkworm Authors

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

#pragma once

#include <optional>
#include <vector>

#include <absl/container/btree_map.h>
#include <absl/container/btree_set.h>
#include <absl/container/flat_hash_map.h>
#include <absl/container/flat_hash_set.h>

#include <silkworm/core/state/state.hpp>
#include <silkworm/core/trie/hash_builder.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/receipt.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/mdbx/mdbx.hpp>
#include <silkworm/db/util.hpp>

namespace silkworm::db {

class Buffer : public State {
  public:
    // txn must be valid (its handle != nullptr)
    explicit Buffer(RWTxn& txn, BlockNum prune_history_threshold,
                    std::optional<BlockNum> historical_block = std::nullopt)
        : txn_{txn}, access_layer_{txn_}, prune_history_threshold_{prune_history_threshold}, historical_block_{historical_block} {}

    /** @name Readers */
    //!@{

    [[nodiscard]] std::optional<Account> read_account(const evmc::address& address) const noexcept override;

    [[nodiscard]] ByteView read_code(const evmc::bytes32& code_hash) const noexcept override;

    [[nodiscard]] evmc::bytes32 read_storage(const evmc::address& address, uint64_t incarnation,
                                             const evmc::bytes32& location) const noexcept override;

    /** Previous non-zero incarnation of an account; 0 if none exists. */
    [[nodiscard]] uint64_t previous_incarnation(const evmc::address& address) const noexcept override;

    [[nodiscard]] std::optional<BlockHeader> read_header(uint64_t block_number,
                                                         const evmc::bytes32& block_hash) const noexcept override;

    [[nodiscard]] bool read_body(uint64_t block_number, const evmc::bytes32& block_hash,
                                 BlockBody& out) const noexcept override;

    [[nodiscard]] std::optional<intx::uint256> total_difficulty(
        uint64_t block_number, const evmc::bytes32& block_hash) const noexcept override;

    [[nodiscard]] evmc::bytes32 state_root_hash() const override;

    [[nodiscard]] uint64_t current_canonical_block() const override;

    [[nodiscard]] std::optional<evmc::bytes32> canonical_hash(uint64_t block_number) const override;

    //!@}

    void insert_block(const Block& block, const evmc::bytes32& hash) override;

    void canonize_block(uint64_t block_number, const evmc::bytes32& block_hash) override;

    void decanonize_block(uint64_t block_number) override;

    void insert_receipts(uint64_t block_number, const std::vector<Receipt>& receipts) override;

    void insert_call_traces(BlockNum block_number, const CallTraces& traces) override;

    /** @name State changes
     *  Change sets are backward changes of the state, i.e. account/storage values <em>at the beginning of a block</em>.
     */
    //!@{

    /** Mark the beginning of a new block.
     * Must be called prior to calling update_account/update_account_code/update_storage.
     */
    void begin_block(uint64_t block_number) override;

    void update_account(const evmc::address& address, std::optional<Account> initial,
                        std::optional<Account> current) override;

    void update_account_code(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& code_hash,
                             ByteView code) override;

    void update_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location,
                        const evmc::bytes32& initial, const evmc::bytes32& current) override;

    void unwind_state_changes(uint64_t block_number) override;

    //!@}

    //! Account (backward) changes per block
    [[nodiscard]] const absl::btree_map<uint64_t, AccountChanges>& account_changes() const {
        return block_account_changes_;
    }

    //! Storage (backward) changes per block
    [[nodiscard]] const absl::btree_map<uint64_t, StorageChanges>& storage_changes() const {
        return block_storage_changes_;
    }

    //! \brief Approximate size of accrued state in bytes.
    [[nodiscard]] size_t current_batch_state_size() const noexcept { return batch_state_size_; }

    //! \brief Approximate size of accrued history in bytes.
    [[nodiscard]] size_t current_batch_history_size() const noexcept { return batch_history_size_; }

    //! \brief Persists *all* accrued contents into db
    //! \remarks write_history_to_db is implicitly called
    //! @param write_change_sets flag indicating if state changes should be written or not (default: true)
    void write_to_db(bool write_change_sets = true);

    //! \brief Persist *history* accrued contents into db
    //! @param write_change_sets flag indicating if state changes should be written or not (default: true)
    void write_history_to_db(bool write_change_sets = true);

    //! \brief Persists *state* accrued contents into db
    void write_state_to_db();

  private:
    RWTxn& txn_;
    db::DataModel access_layer_;
    uint64_t prune_history_threshold_;
    std::optional<uint64_t> historical_block_{};

    absl::btree_map<Bytes, BlockHeader> headers_{};
    absl::btree_map<Bytes, BlockBody> bodies_{};
    absl::btree_map<Bytes, intx::uint256> difficulty_{};

    // State

    mutable absl::flat_hash_map<evmc::address, std::optional<Account>> accounts_;

    // address -> incarnation -> location -> value
    using Storage = absl::flat_hash_map<evmc::bytes32, evmc::bytes32>;
    using StorageByIncarnation = absl::btree_map<uint64_t, Storage>;
    mutable absl::flat_hash_map<evmc::address, StorageByIncarnation> storage_;

    absl::btree_map<evmc::address, uint64_t> incarnations_;
    absl::btree_map<evmc::bytes32, Bytes> hash_to_code_;
    absl::btree_map<Bytes, evmc::bytes32> storage_prefix_to_code_hash_;

    // History and changesets

    absl::btree_map<BlockNum, AccountChanges> block_account_changes_;  // per block
    absl::btree_map<BlockNum, StorageChanges> block_storage_changes_;  // per block
    absl::btree_map<Bytes, Bytes> receipts_;
    absl::btree_map<Bytes, Bytes> logs_;
    absl::btree_map<BlockNum, absl::btree_set<Bytes>> call_traces_;

    mutable size_t batch_state_size_{0};    // Accounts in memory data for state
    mutable size_t batch_history_size_{0};  // Accounts in memory data for history

    // Current block stuff
    uint64_t block_number_{0};
    absl::flat_hash_set<evmc::address> changed_storage_;
};

}  // namespace silkworm::db
