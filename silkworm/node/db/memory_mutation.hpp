/*
   Copyright 2023 The Silkworm Authors

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

#include <filesystem>
#include <map>
#include <string>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/node/db/access_layer.hpp>

namespace silkworm::db {

class MemoryOverlay {
  public:
    explicit MemoryOverlay(const std::filesystem::path& tmp_dir);
    MemoryOverlay(MemoryOverlay&& other) noexcept;

    ::mdbx::txn_managed start_rw_tx();

  private:
    ::mdbx::env_managed memory_env_;
};

class MemoryMutationCursor;

class MemoryMutation : public RWTxn {
  public:
    MemoryMutation(MemoryOverlay& memory_db, ROTxn* txn);
    ~MemoryMutation() override;

    [[nodiscard]] bool is_table_cleared(const std::string& table) const;
    [[nodiscard]] bool is_entry_deleted(const std::string& table, const Slice& key) const;
    [[nodiscard]] bool has_map(const std::string& bucket_name) const;

    [[nodiscard]] db::ROTxn* external_txn() const { return txn_; }

    void update_txn(ROTxn* txn);

    std::unique_ptr<ROCursor> ro_cursor(const MapConfig& config) override;
    std::unique_ptr<ROCursorDupSort> ro_cursor_dup_sort(const MapConfig& config) override;
    std::unique_ptr<RWCursor> rw_cursor(const MapConfig& config) override;
    std::unique_ptr<RWCursorDupSort> rw_cursor_dup_sort(const MapConfig& config) override;

    bool erase(const MapConfig& config, const Slice& key);
    bool erase(const MapConfig& config, const Slice& key, const Slice& value);

    bool clear_table(const std::string& table);

    void flush(db::RWTxn& rw_txn);
    void rollback();

  private:
    std::unique_ptr<MemoryMutationCursor> make_cursor(const MapConfig& config);

    MemoryOverlay& memory_db_;
    db::ROTxn* txn_;
    std::map<std::string, std::map<Slice, bool>> deleted_entries_;
    std::map<std::string, bool> cleared_tables_;
};

}  // namespace silkworm::db
