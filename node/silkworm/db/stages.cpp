/*
   Copyright 2020-2022 The Silkworm Authors

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

#include "stages.hpp"

#include <silkworm/common/endian.hpp>

namespace silkworm::db::stages {

static BlockNum get_stage_data(mdbx::txn& txn, const char* stage_name, const db::MapConfig& domain,
                               const char* key_prefix = nullptr) {
    if (!is_known_stage(stage_name)) {
        throw std::invalid_argument("Unknown stage name " + std::string(stage_name));
    }

    try {
        db::Cursor src(txn, domain);
        std::string item_key{stage_name};
        if (key_prefix) {
            item_key.insert(0, std::string(key_prefix));
        }
        auto data{src.find(mdbx::slice(item_key.c_str()), /*throw_notfound*/ false)};
        if (!data) {
            return 0;
        } else if (data.value.size() != sizeof(uint64_t)) {
            throw std::length_error("Expected 8 bytes of data got " + std::to_string(data.value.size()));
        }
        return endian::load_big_u64(static_cast<uint8_t*>(data.value.data()));
    } catch (const mdbx::exception& ex) {
        std::string what("Error in " + std::string(__FUNCTION__) + " " + std::string(ex.what()));
        throw std::runtime_error(what);
    }
}

static void set_stage_data(mdbx::txn& txn, const char* stage_name, uint64_t block_num, const db::MapConfig& domain,
                           const char* key_prefix = nullptr) {
    if (!is_known_stage(stage_name)) {
        throw std::invalid_argument("Unknown stage name");
    }

    try {
        std::string item_key{stage_name};
        if (key_prefix) {
            item_key.insert(0, std::string(key_prefix));
        }
        Bytes stage_progress(sizeof(block_num), 0);
        endian::store_big_u64(stage_progress.data(), block_num);
        db::Cursor target(txn, domain);
        mdbx::slice key(item_key.c_str());
        mdbx::slice value{db::to_slice(stage_progress)};
        target.upsert(key, value);
    } catch (const mdbx::exception& ex) {
        std::string what("Error in " + std::string(__FUNCTION__) + " " + std::string(ex.what()));
        throw std::runtime_error(what);
    }
}

BlockNum read_stage_progress(mdbx::txn& txn, const char* stage_name) {
    return get_stage_data(txn, stage_name, silkworm::db::table::kSyncStageProgress);
}

BlockNum read_stage_prune_progress(mdbx::txn& txn, const char* stage_name) {
    return get_stage_data(txn, stage_name, silkworm::db::table::kSyncStageProgress, "prune_");
}

void write_stage_progress(mdbx::txn& txn, const char* stage_name, BlockNum block_num) {
    set_stage_data(txn, stage_name, block_num, silkworm::db::table::kSyncStageProgress);
}

void write_stage_prune_progress(mdbx::txn& txn, const char* stage_name, BlockNum block_num) {
    set_stage_data(txn, stage_name, block_num, silkworm::db::table::kSyncStageProgress, "prune_");
}

BlockNum read_stage_unwind(mdbx::txn& txn, const char* stage_name) {
    return get_stage_data(txn, stage_name, silkworm::db::table::kSyncStageUnwind);
}

void write_stage_unwind(mdbx::txn& txn, const char* stage_name, BlockNum block_num) {
    set_stage_data(txn, stage_name, block_num, silkworm::db::table::kSyncStageUnwind);
}

bool is_known_stage(const char* name) {
    if (strlen(name)) {
        for (auto stage : kAllStages) {
            if (strcmp(stage, name) == 0) {
                return true;
            }
        }
    }
    return false;
}

}  // namespace silkworm::db::stages
