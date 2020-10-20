/*
   Copyright 2020 The Silkworm Authors

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

#ifndef SILKWORM_DB_BUFFER_H_
#define SILKWORM_DB_BUFFER_H_

#include <absl/container/flat_hash_map.h>
#include <absl/container/flat_hash_set.h>

#include <evmc/evmc.hpp>
#include <map>
#include <optional>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/change.hpp>
#include <silkworm/types/account.hpp>
#include <silkworm/types/block.hpp>

namespace silkworm::db {

class Buffer {
   public:
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;

    explicit Buffer(lmdb::Transaction* txn, std::optional<uint64_t> historical_block = std::nullopt)
        : txn_{txn}, historical_block_{historical_block} {}

    /** @name Readers */
    ///@{
    std::optional<Account> read_account(const evmc::address& address) const noexcept;

    Bytes read_code(const evmc::bytes32& code_hash) const noexcept;

    evmc::bytes32 read_storage(const evmc::address& address, uint64_t incarnation,
                               const evmc::bytes32& key) const noexcept;

    /** Previous non-zero incarnation of an account; 0 if none exists. */
    uint64_t previous_incarnation(const evmc::address& address) const noexcept;

    std::optional<BlockHeader> read_header(uint64_t block_number, const evmc::bytes32& block_hash) const noexcept;
    ///@}

    void insert_header(BlockHeader block_header);

    void insert_receipts(Bytes block_key, Bytes receipts);

    /** @name State changes
     *  Change sets are backward changes of the state, i.e. account/storage values <em>at the beginning of a block</em>.
     */
    ///@{
    /** Mark the beggining of a new block.
     * Must be called prior to calling update_account/update_account_code/update_storage.
     */
    void begin_new_block(uint64_t block_number);

    void update_account(const evmc::address& address, std::optional<Account> initial, std::optional<Account> current);

    void update_account_code(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& code_hash,
                             ByteView code);

    void update_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& key,
                        const evmc::bytes32& initial, const evmc::bytes32& current);

    /** Account (backward) changes per block.*/
    const std::map<uint64_t, AccountChanges>& account_changes() const { return account_changes_; }

    /** Storage (backward) changes per block.*/
    const std::map<uint64_t, StorageChanges>& storage_changes() const { return storage_changes_; }
    ///@}

    /** Whether there's enough pending data in the buffer to be written into the database. */
    bool full_enough() const;

    void write_to_db();

    /** Optimal number of entries to keep in memory before commiting to the database. */
    size_t optimal_batch_size{500'000};

   private:
    void write_to_state_table();

    lmdb::Transaction* txn_{nullptr};
    std::optional<uint64_t> historical_block_{};

    std::map<Bytes, BlockHeader> headers_{};
    absl::flat_hash_map<evmc::address, std::optional<Account>> accounts_;

    // address -> key -> value
    absl::flat_hash_map<evmc::address, std::map<evmc::bytes32, evmc::bytes32>> default_incarnation_storage_;

    // address -> incarnation -> key -> value
    absl::flat_hash_map<evmc::address, std::map<uint64_t, std::map<evmc::bytes32, evmc::bytes32>>>
        custom_incarnation_storage_;

    std::map<evmc::address, uint64_t> incarnations_;
    std::map<evmc::bytes32, Bytes> hash_to_code_;
    std::map<Bytes, evmc::bytes32> storage_prefix_to_code_hash_;
    std::map<Bytes, Bytes> receipts_;

    size_t number_of_entries{0};

    // Stuff related to change sets
    uint64_t current_block_number_{0};
    absl::flat_hash_set<evmc::address> changed_storage_;
    std::map<uint64_t, AccountChanges> account_changes_;
    std::map<uint64_t, StorageChanges> storage_changes_;
};

}  // namespace silkworm::db

#endif  // SILKWORM_DB_BUFFER_H_
