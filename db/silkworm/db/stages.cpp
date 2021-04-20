/*
   Copyright 2020-2021 The Silkworm Authors

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

#include <boost/endian/conversion.hpp>

namespace silkworm::db::stages {

namespace {

    bool is_known_stage(const char* name) {
        for (auto stage : AllStages) {
            if (strcmp(stage, name) == 0) {
                return true;
            }
        }
        return false;
    }

    uint64_t get_stage_data(lmdb::Transaction& txn, const char* stage_name, const lmdb::TableConfig& domain) {

        if (!is_known_stage(stage_name)) {
            throw std::invalid_argument("Unknown stage name " + std::string(stage_name));
        }

        MDB_val mdb_key{std::strlen(stage_name), const_cast<char*>(stage_name)};
        auto data{txn.get(domain, &mdb_key)};
        if ((*data).size() != sizeof(uint64_t)) {
            throw std::length_error("Expected 8 bytes of data got " + std::to_string((*data).size()));
        }
        return boost::endian::load_big_u64(data->c_str());
    }

    void set_stage_data(lmdb::Transaction& txn, const char* stage_name, uint64_t block_num,
                        const lmdb::TableConfig& domain) {

        if (!is_known_stage(stage_name)) {
            throw std::invalid_argument("Unknown stage name");
        }

        Bytes stage_progress(sizeof(block_num), 0);
        boost::endian::store_big_u64(stage_progress.data(), block_num);
        MDB_val mdb_key{std::strlen(stage_name), const_cast<char*>(stage_name)};
        MDB_val mdb_data{db::to_mdb_val(stage_progress)};
        lmdb::err_handler(txn.put(domain, &mdb_key, &mdb_data));
    }

}  // namespace

uint64_t get_stage_progress(lmdb::Transaction& txn, const char* stage_name) {
    return get_stage_data(txn, stage_name, silkworm::db::table::kSyncStageProgress);
}

void set_stage_progress(lmdb::Transaction& txn, const char* stage_name, uint64_t block_num) {
    set_stage_data(txn, stage_name, block_num, silkworm::db::table::kSyncStageProgress);
}

uint64_t get_stage_unwind(lmdb::Transaction& txn, const char* stage_name) {
    return get_stage_data(txn, stage_name, silkworm::db::table::kSyncStageUnwind);
}

void set_stage_unwind(lmdb::Transaction& txn, const char* stage_name, uint64_t block_num) {
    set_stage_data(txn, stage_name, block_num, silkworm::db::table::kSyncStageUnwind);
}

void clear_stage_unwind(lmdb::Transaction& txn, const char* stage_name) {
    set_stage_data(txn, stage_name, 0, silkworm::db::table::kSyncStageUnwind);
}

}  // namespace silkworm::db::stages
