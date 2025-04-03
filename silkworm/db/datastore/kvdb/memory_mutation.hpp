// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <functional>
#include <map>
#include <string>

#include "mdbx.hpp"

namespace silkworm::datastore::kvdb {

class MemoryDatabase {
  public:
    explicit MemoryDatabase(const std::filesystem::path& tmp_dir);
    MemoryDatabase();

    MemoryDatabase(MemoryDatabase&& other) noexcept = default;
    MemoryDatabase& operator=(MemoryDatabase&&) noexcept = default;

    ::mdbx::txn_managed start_rw_txn();

  private:
    ::mdbx::env_managed memory_env_;
};

class MemoryOverlay {
  public:
    MemoryOverlay(
        const std::filesystem::path& tmp_dir,
        ROTxn* txn,
        std::function<std::optional<MapConfig>(const std::string& map_name)> get_map_config,
        std::string sequence_map_name);

    MemoryOverlay(MemoryOverlay&& other) noexcept = default;
    MemoryOverlay& operator=(MemoryOverlay&&) noexcept = default;

    ROTxn* external_txn() const { return txn_; }
    void update_txn(ROTxn* txn);

    ::mdbx::txn_managed start_rw_txn();

    std::optional<MapConfig> map_config(const std::string& map_name);
    MapConfig sequence_map_config();

  private:
    MemoryDatabase memory_db_;
    ROTxn* txn_;
    std::function<std::optional<MapConfig>(const std::string& map_name)> get_map_config_;
    std::string sequence_map_name_;
};

class MemoryMutationCursor;

class MemoryMutation : public RWTxnManaged {
  public:
    explicit MemoryMutation(MemoryOverlay& overlay);

    MemoryMutation(MemoryMutation&& other) noexcept = default;
    MemoryMutation& operator=(MemoryMutation&&) noexcept = delete;

    ~MemoryMutation() override;

    bool is_table_cleared(const std::string& table) const;
    bool is_entry_deleted(const std::string& table, const Slice& key) const;
    bool is_dup_deleted(const std::string& table, const Slice& key, const Slice& value) const;
    bool has_map(const std::string& bucket_name) const;

    ROTxn* external_txn() const { return overlay_.external_txn(); }

    void update_txn(ROTxn* txn);

    std::unique_ptr<ROCursor> ro_cursor(const MapConfig& config) override;
    std::unique_ptr<ROCursorDupSort> ro_cursor_dup_sort(const MapConfig& config) override;
    std::unique_ptr<RWCursor> rw_cursor(const MapConfig& config) override;
    std::unique_ptr<RWCursorDupSort> rw_cursor_dup_sort(const MapConfig& config) override;

    bool erase(const MapConfig& config, const Slice& key);
    bool erase(const MapConfig& config, const Slice& key, const Slice& value);
    void upsert(const MapConfig& config, const Slice& key, const Slice& value);

    bool clear_table(const std::string& table);

    void flush(RWTxn& rw_txn);
    void rollback();
    void reopen();

  private:
    std::unique_ptr<MemoryMutationCursor> make_cursor(const MapConfig& config);

    MemoryOverlay& overlay_;
    std::map<std::string, std::map<Slice, bool>> deleted_entries_;
    std::map<std::string, std::map<Slice, std::map<Slice, bool>>> deleted_dups_;
    std::map<std::string, bool> cleared_tables_;
};

}  // namespace silkworm::datastore::kvdb
