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

#include <silkworm/infra/common/directories.hpp>
#include <silkworm/node/db/tables.hpp>

#include "memory_mutation_cursor.hpp"

namespace silkworm::db {

MemoryOverlay::MemoryOverlay(const std::filesystem::path& tmp_dir) {
    DataDirectory data_dir{tmp_dir / "silkworm_mem_db"};
    data_dir.deploy();

    EnvConfig memory_config{
        .path = data_dir.chaindata().path().string(),
        .create = true,
        .exclusive = true,
        .in_memory = true,
        .max_size = 512_Mebi,
    };
    memory_env_ = db::open_env(memory_config);

    // Create predefined tables for chaindata schema
    RWTxn txn{memory_env_};
    table::check_or_create_chaindata_tables(txn);
    txn.commit_and_stop();
}

MemoryOverlay::MemoryOverlay(MemoryOverlay&& other) noexcept : memory_env_(std::move(other.memory_env_)) {}

::mdbx::txn_managed MemoryOverlay::start_rw_tx() {
    return memory_env_.start_write();
}

MemoryMutation::MemoryMutation(MemoryOverlay& memory_db, ROTxn* txn)
    : RWTxn{::mdbx::txn_managed{}}, memory_db_(memory_db), txn_(txn) {
    managed_txn_ = memory_db_.start_rw_tx();

    // Initialize sequences
    db::PooledCursor cursor{*txn_, db::table::kSequence};
    db::PooledCursor memory_cursor{managed_txn_, db::table::kSequence};
    for (auto result = cursor.to_first(false); result; result = cursor.to_next(false)) {
        memory_cursor.put(result.key, &result.value, MDBX_put_flags_t::MDBX_UPSERT);
    }
}

MemoryMutation::~MemoryMutation() {
    rollback();
}

bool MemoryMutation::is_table_cleared(const std::string& bucket_name) const {
    return cleared_tables_.contains(bucket_name);
}

bool MemoryMutation::is_entry_deleted(const std::string& bucket_name, const Slice& key) const {
    if (!deleted_entries_.contains(bucket_name)) {
        return false;
    }
    return deleted_entries_.at(bucket_name) == key;
}

bool MemoryMutation::has_map(const std::string& bucket_name) const {
    return db::has_map(*txn_, bucket_name.c_str());
}

void MemoryMutation::update_txn(ROTxn* txn) {
    txn_ = txn;
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
