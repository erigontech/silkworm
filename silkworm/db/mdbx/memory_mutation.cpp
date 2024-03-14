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

#include "memory_mutation.hpp"

#include <gsl/util>

#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>

#include "memory_mutation_cursor.hpp"

namespace silkworm::db {

MemoryDatabase::MemoryDatabase(const std::filesystem::path& tmp_dir) {
    DataDirectory data_dir{tmp_dir};
    data_dir.deploy();

    EnvConfig memory_config{
        .path = data_dir.chaindata().path().string(),
        .create = true,
        .exclusive = true,
        .in_memory = true,
        .max_size = 512_Mebi,
    };
    memory_env_ = db::open_env(memory_config);
}

MemoryDatabase::MemoryDatabase() : MemoryDatabase(TemporaryDirectory::get_unique_temporary_path()) {}

::mdbx::txn_managed MemoryDatabase::start_rw_txn() {
    return memory_env_.start_write();
}

MemoryOverlay::MemoryOverlay(
    const std::filesystem::path& tmp_dir,
    silkworm::db::ROTxn* txn,
    std::function<std::optional<MapConfig>(const std::string& map_name)> get_map_config,
    std::string sequence_map_name)
    : memory_db_(tmp_dir),
      txn_(txn),
      get_map_config_(std::move(get_map_config)),
      sequence_map_name_(std::move(sequence_map_name)) {}

void MemoryOverlay::update_txn(ROTxn* txn) {
    txn_ = txn;
}

::mdbx::txn_managed MemoryOverlay::start_rw_txn() {
    return memory_db_.start_rw_txn();
}

std::optional<MapConfig> MemoryOverlay::map_config(const std::string& map_name) {
    return get_map_config_(map_name);
}

MapConfig MemoryOverlay::sequence_map_config() {
    return *map_config(sequence_map_name_);
}

MemoryMutation::MemoryMutation(MemoryOverlay& overlay)
    : RWTxnManaged(overlay.start_rw_txn()),
      overlay_(overlay) {
    // Initialize sequences
    const auto sequence_map_config = overlay.sequence_map_config();
    db::PooledCursor cursor{*overlay_.external_txn(), sequence_map_config};
    db::PooledCursor memory_cursor{managed_txn_, sequence_map_config};
    for (auto result = cursor.to_first(false); result; result = cursor.to_next(false)) {
        memory_cursor.put(result.key, &result.value, MDBX_put_flags_t::MDBX_UPSERT);
    }
}

MemoryMutation::~MemoryMutation() {
    rollback();
}

void MemoryMutation::reopen() {
    managed_txn_ = overlay_.start_rw_txn();
}

bool MemoryMutation::is_table_cleared(const std::string& table) const {
    return cleared_tables_.contains(table);
}

bool MemoryMutation::is_entry_deleted(const std::string& table, const Slice& key) const {
    if (!deleted_entries_.contains(table)) {
        return false;
    }
    const auto& deleted_slices = deleted_entries_.at(table);
    return deleted_slices.find(key) != deleted_slices.cend();
}

bool MemoryMutation::has_map(const std::string& bucket_name) const {
    return db::has_map(*overlay_.external_txn(), bucket_name.c_str());
}

void MemoryMutation::update_txn(ROTxn* txn) {
    overlay_.update_txn(txn);
}

std::unique_ptr<ROCursor> MemoryMutation::ro_cursor(const MapConfig& config) {
    return make_cursor(config);
}

std::unique_ptr<ROCursorDupSort> MemoryMutation::ro_cursor_dup_sort(const MapConfig& config) {
    return make_cursor(config);
}

std::unique_ptr<RWCursor> MemoryMutation::rw_cursor(const MapConfig& config) {
    return make_cursor(config);
}

std::unique_ptr<RWCursorDupSort> MemoryMutation::rw_cursor_dup_sort(const MapConfig& config) {
    return make_cursor(config);
}

bool MemoryMutation::erase(const MapConfig& config, const Slice& key) {
    deleted_entries_[config.name][key] = true;
    const auto handle{managed_txn_.open_map(config.name, config.key_mode, config.value_mode)};
    return managed_txn_.erase(handle, key);
}

bool MemoryMutation::erase(const MapConfig& config, const Slice& key, const Slice& value) {
    deleted_entries_[config.name][key] = true;
    const auto handle{managed_txn_.open_map(config.name, config.key_mode, config.value_mode)};
    return managed_txn_.erase(handle, key, value);
}

bool MemoryMutation::clear_table(const std::string& table) {
    cleared_tables_[table] = true;
    return managed_txn_.clear_map(table.c_str(), /*throw_if_absent=*/false);
}

void MemoryMutation::flush(db::RWTxn& rw_txn) {
    reopen();

    // Obliterate buckets that need to be deleted
    for (const auto& [table, _] : cleared_tables_) {
        rw_txn->clear_map(table);
    }

    // Obliterate entries that need to be deleted
    for (const auto& [table, keys] : this->deleted_entries_) {
        const auto table_config = overlay_.map_config(table);
        if (!table_config) {
            SILK_WARN << "Unknown table " << table << " in memory mutation, ignored";
            continue;
        }
        const auto map_handle = db::open_map(rw_txn, *table_config);
        for (const auto& [key, _] : keys) {
            rw_txn->erase(map_handle, key);
        }
    }

    // Iterate over each touched bucket and apply changes accordingly
    const auto tables = db::list_maps(managed_txn_);
    for (const auto& table : tables) {
        const auto table_config = overlay_.map_config(table);
        if (!table_config) {
            SILK_WARN << "Unknown table " << table << " in memory mutation, ignored";
            continue;
        }

        const auto mem_cursor = make_cursor(*table_config);
        const auto db_cursor = rw_txn.rw_cursor_dup_sort(*table_config);

        SILK_TRACE << "Apply memory mutation changes for table: " << table_config->name;

        auto mem_cursor_result = mem_cursor->to_first(/*throw_notfound =*/false);
        while (mem_cursor_result.done) {
            const auto& mem_key = mem_cursor_result.key;
            const auto& mem_value = mem_cursor_result.value;
            db_cursor->upsert(mem_key, mem_value);

            SILK_TRACE << "Memory mutation change key: " << mem_key.as_string() << " value: " << mem_value.as_string();

            mem_cursor_result = mem_cursor->to_next(/*throw_notfound =*/false);
        }
    }

    rollback();
}

void MemoryMutation::rollback() {
    // Idempotent rollback: abort iff transaction is still alive (i.e. handle is not null)
    if (managed_txn_) {
        managed_txn_.abort();
    }
}

std::unique_ptr<MemoryMutationCursor> MemoryMutation::make_cursor(const MapConfig& config) {
    return std::make_unique<MemoryMutationCursor>(*this, config);
}

}  // namespace silkworm::db
