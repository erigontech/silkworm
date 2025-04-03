// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "stages.hpp"

#include <stdexcept>

#include <silkworm/core/common/endian.hpp>

namespace silkworm::db::stages {

using namespace silkworm::datastore::kvdb;

static BlockNum get_stage_data(ROTxn& txn, const char* stage_name, const MapConfig& domain,
                               const char* key_prefix = nullptr) {
    if (!is_known_stage(stage_name)) {
        throw std::invalid_argument("Unknown stage name " + std::string(stage_name));
    }

    try {
        auto cursor = txn.ro_cursor(domain);
        std::string item_key{stage_name};
        if (key_prefix) {
            item_key.insert(0, std::string(key_prefix));
        }
        auto data{cursor->find(mdbx::slice(item_key.c_str()), /*throw_notfound*/ false)};
        if (!data) {
            return 0;
        }
        if (data.value.size() != sizeof(uint64_t)) {
            throw std::length_error("Expected 8 bytes of data got " + std::to_string(data.value.size()));
        }
        return endian::load_big_u64(static_cast<uint8_t*>(data.value.data()));
    } catch (const mdbx::exception& ex) {
        std::string what("Error in " + std::string(__FUNCTION__) + " " + std::string(ex.what()));
        throw std::runtime_error(what);
    }
}

static void set_stage_data(RWTxn& txn, const char* stage_name, uint64_t block_num, const MapConfig& domain,
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
        auto target = txn.rw_cursor(domain);
        mdbx::slice key(item_key.c_str());
        mdbx::slice value = datastore::kvdb::to_slice(stage_progress);
        target->upsert(key, value);
    } catch (const mdbx::exception& ex) {
        std::string what("Error in " + std::string(__FUNCTION__) + " " + std::string(ex.what()));
        throw std::runtime_error(what);
    }
}

BlockNum read_stage_progress(ROTxn& txn, const char* stage_name) {
    return get_stage_data(txn, stage_name, silkworm::db::table::kSyncStageProgress);
}

BlockNum read_stage_prune_progress(ROTxn& txn, const char* stage_name) {
    return get_stage_data(txn, stage_name, silkworm::db::table::kSyncStageProgress, "prune_");
}

void write_stage_progress(RWTxn& txn, const char* stage_name, BlockNum block_num) {
    set_stage_data(txn, stage_name, block_num, silkworm::db::table::kSyncStageProgress);
}

void write_stage_prune_progress(RWTxn& txn, const char* stage_name, BlockNum block_num) {
    set_stage_data(txn, stage_name, block_num, silkworm::db::table::kSyncStageProgress, "prune_");
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
