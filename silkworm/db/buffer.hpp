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

#include <absl/container/btree_map.h>
#include <absl/container/flat_hash_map.h>
#include <absl/container/flat_hash_set.h>

#include <evmc/evmc.hpp>
#include <optional>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/change.hpp>
#include <silkworm/db/state_buffer.hpp>
#include <silkworm/types/account.hpp>
#include <silkworm/types/block.hpp>
#include <vector>

namespace silkworm::db {

class Buffer : public StateBuffer {
  public:
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;

    explicit Buffer(lmdb::Transaction* txn, std::optional<uint64_t> historical_block = std::nullopt)
        : txn_{txn}, historical_block_{historical_block} {}

    /** @name Readers */
    ///@{
    std::optional<Account> read_account(const evmc::address& address) const noexcept override;

    Bytes read_code(const evmc::bytes32& code_hash) const noexcept override;

    evmc::bytes32 read_storage(const evmc::address& address, uint64_t incarnation,
                               const evmc::bytes32& key) const noexcept override;

    /** Previous non-zero incarnation of an account; 0 if none exists. */
    uint64_t previous_incarnation(const evmc::address& address) const noexcept override;

    std::optional<BlockHeader> read_header(uint64_t block_number,
                                           const evmc::bytes32& block_hash) const noexcept override;
    ///@}

    void insert_header(const BlockHeader& block_header) override;

    /** @name State changes
     *  Change sets are backward changes of the state, i.e. account/storage values <em>at the beginning of a block</em>.
     */
    ///@{
    /** Mark the beggining of a new block.
     * Must be called prior to calling update_account/update_account_code/update_storage.
     */
    void begin_block(uint64_t block_number) override;

    void update_account(const evmc::address& address, std::optional<Account> initial,
                        std::optional<Account> current) override;

    void update_account_code(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& code_hash,
                             ByteView code) override;

    void update_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& key,
                        const evmc::bytes32& initial, const evmc::bytes32& current) override;

    /** Mark the end of a block.
     * Must be called after all invocations of update_account/update_account_code/update_storage.
     */
    void end_block() override;

    /** Account (backward) changes for the current block.*/
    const AccountChanges& account_changes() const { return current_account_changes_; }

    /** Storage (backward) changes for the current block.*/
    const StorageChanges& storage_changes() const { return current_storage_changes_; }
    ///@}

    /** Approximate size of accumulated DB changes in bytes.*/
    size_t current_batch_size() const noexcept { return batch_size_; }

    void write_to_db();

  private:
    void write_to_state_table();

    lmdb::Transaction* txn_{nullptr};
    std::optional<uint64_t> historical_block_{};

    absl::btree_map<Bytes, BlockHeader> headers_{};
    absl::flat_hash_map<evmc::address, std::optional<Account>> accounts_;

    // address -> incarnation -> key -> value
    absl::flat_hash_map<evmc::address, absl::btree_map<uint64_t, absl::flat_hash_map<evmc::bytes32, evmc::bytes32>>>
        storage_;

    absl::btree_map<uint64_t, Bytes> account_changes_;
    absl::btree_map<uint64_t, Bytes> storage_changes_;

    absl::btree_map<evmc::address, uint64_t> incarnations_;
    absl::btree_map<evmc::bytes32, Bytes> hash_to_code_;
    absl::btree_map<Bytes, evmc::bytes32> storage_prefix_to_code_hash_;

    size_t batch_size_{0};

    // Current block stuff
    uint64_t current_block_number_{0};
    absl::flat_hash_set<evmc::address> changed_storage_;
    AccountChanges current_account_changes_;
    StorageChanges current_storage_changes_;
};

}  // namespace silkworm::db

#endif  // SILKWORM_DB_BUFFER_H_
