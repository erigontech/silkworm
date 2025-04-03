// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
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
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/db/util.hpp>

namespace silkworm::db {

struct BufferDataModel {
    virtual ~BufferDataModel() = default;
    virtual std::optional<BlockHeader> read_header(BlockNum block_num, const Hash& block_hash) const = 0;
    [[nodiscard]] virtual bool read_body(BlockNum block_num, HashAsArray hash, bool read_senders, BlockBody& body) const = 0;
};

class BufferROTxDataModel : public BufferDataModel {
  public:
    explicit BufferROTxDataModel(ROTxn& tx) : tx_{tx} {}
    ~BufferROTxDataModel() override = default;
    std::optional<BlockHeader> read_header(BlockNum block_num, const Hash& block_hash) const override {
        return db::read_header(tx_, block_num, block_hash);
    }
    [[nodiscard]] bool read_body(BlockNum block_num, HashAsArray hash, bool read_senders, BlockBody& body) const override {
        return db::read_body(tx_, block_num, hash, read_senders, body);
    }

  private:
    ROTxn& tx_;
};

class BufferFullDataModel : public BufferDataModel {
  public:
    explicit BufferFullDataModel(DataModel data_model) : data_model_{data_model} {}
    ~BufferFullDataModel() override = default;
    std::optional<BlockHeader> read_header(BlockNum block_num, const Hash& block_hash) const override {
        return data_model_.read_header(block_num, block_hash);
    }
    [[nodiscard]] bool read_body(BlockNum block_num, HashAsArray hash, bool read_senders, BlockBody& body) const override {
        return data_model_.read_body(block_num, hash, read_senders, body);
    }

  private:
    DataModel data_model_;
};

class Buffer : public State {
  public:
    explicit Buffer(
        RWTxn& txn,
        std::unique_ptr<BufferDataModel> data_model)
        : txn_{txn},
          data_model_{std::move(data_model)} {}

    /** @name Settings */
    //!@{

    void set_prune_history_threshold(BlockNum prune_history_threshold) {
        prune_history_threshold_ = prune_history_threshold;
    }

    void set_historical_block(BlockNum historical_block) {
        historical_block_ = historical_block;
    }

    void set_memory_limit(size_t memory_limit) {
        memory_limit_ = memory_limit;
    }

    //!@}

    /** @name Readers */
    //!@{

    std::optional<Account> read_account(const evmc::address& address) const noexcept override;

    ByteView read_code(const evmc::address& address, const evmc::bytes32& code_hash) const noexcept override;

    evmc::bytes32 read_storage(
        const evmc::address& address,
        uint64_t incarnation,
        const evmc::bytes32& location) const noexcept override;

    /** Previous non-zero incarnation of an account; 0 if none exists. */
    uint64_t previous_incarnation(const evmc::address& address) const noexcept override;

    std::optional<BlockHeader> read_header(
        uint64_t block_num,
        const evmc::bytes32& block_hash) const noexcept override;

    [[nodiscard]] bool read_body(
        uint64_t block_num,
        const evmc::bytes32& block_hash,
        BlockBody& out) const noexcept override;

    std::optional<intx::uint256> total_difficulty(
        uint64_t block_num,
        const evmc::bytes32& block_hash) const noexcept override;

    evmc::bytes32 state_root_hash() const override;

    uint64_t current_canonical_block() const override;

    std::optional<evmc::bytes32> canonical_hash(uint64_t block_num) const override;

    //!@}

    void insert_block(const Block& block, const evmc::bytes32& hash) override;

    void canonize_block(uint64_t block_num, const evmc::bytes32& block_hash) override;

    void decanonize_block(uint64_t block_num) override;

    void insert_receipts(uint64_t block_num, const std::vector<Receipt>& receipts) override;

    void insert_call_traces(BlockNum block_num, const CallTraces& traces) override;

    /** @name State changes
     *  Change sets are backward changes of the state, i.e. account/storage values <em>at the beginning of a block</em>.
     */
    //!@{

    /** Mark the beginning of a new block.
     * Must be called prior to calling update_account/update_account_code/update_storage.
     */
    void begin_block(uint64_t block_num, size_t updated_accounts_count) override;

    void update_account(const evmc::address& address, std::optional<Account> initial,
                        std::optional<Account> current) override;

    void update_account_code(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& code_hash,
                             ByteView code) override;

    void update_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location,
                        const evmc::bytes32& initial, const evmc::bytes32& current) override;

    void unwind_state_changes(uint64_t block_num) override;

    //!@}

    //! Account (backward) changes per block
    const absl::btree_map<uint64_t, AccountChanges>& account_changes() const {
        return block_account_changes_;
    }

    //! Storage (backward) changes per block
    const absl::btree_map<uint64_t, StorageChanges>& storage_changes() const {
        return block_storage_changes_;
    }

    //! \brief Approximate size of accrued state in bytes.
    size_t current_batch_state_size() const noexcept { return batch_state_size_; }

    //! \brief Persists *all* accrued contents into db
    //! \remarks write_history_to_db is implicitly called
    //! @param write_change_sets flag indicating if state changes should be written or not (default: true)
    void write_to_db(bool write_change_sets = true);

    //! \brief Persist *history* accrued contents into db
    //! @param write_change_sets flag indicating if state changes should be written or not (default: true)
    void write_history_to_db(bool write_change_sets = true);

    //! \brief Persists *state* accrued contents into db
    void write_state_to_db();

    class MemoryLimitError : public std::runtime_error {
      public:
        MemoryLimitError() : std::runtime_error("db::Buffer::MemoryLimitError") {}
    };

  private:
    RWTxn& txn_;
    std::unique_ptr<BufferDataModel> data_model_;

    // Settings

    uint64_t prune_history_threshold_{0};
    std::optional<uint64_t> historical_block_;

    size_t memory_limit_{std::numeric_limits<size_t>::max()};

    absl::btree_map<Bytes, BlockHeader> headers_;
    absl::btree_map<Bytes, BlockBody> bodies_;
    absl::btree_map<Bytes, intx::uint256> difficulty_;

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

    // Accounts in memory data for state
    mutable size_t batch_state_size_{0};

    // Current block stuff
    uint64_t block_num_{0};
    absl::flat_hash_set<evmc::address> changed_storage_;
};

}  // namespace silkworm::db
