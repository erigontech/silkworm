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

    uint64_t get_stage_data(mdbx::txn& txn, const char* stage_name, const db::MapConfig& domain) {
        if (!is_known_stage(stage_name)) {
            throw std::invalid_argument("Unknown stage name " + std::string(stage_name));
        }
        auto src{db::open_cursor(txn, domain)};
        auto data{src.find({const_cast<char*>(stage_name), std::strlen(stage_name)}, /*throw_notfound*/ false)};
        if (!data) {
            return 0;
        } else if (data.value.size() != sizeof(uint64_t)) {
            throw std::length_error("Expected 8 bytes of data got " + std::to_string(data.value.size()));
        }
        return boost::endian::load_big_u64(static_cast<uint8_t*>(data.value.iov_base));
    }

    void set_stage_data(mdbx::txn& txn, const char* stage_name, uint64_t block_num, const db::MapConfig& domain) {
        if (!is_known_stage(stage_name)) {
            throw std::invalid_argument("Unknown stage name");
        }

        Bytes stage_progress(sizeof(block_num), 0);
        boost::endian::store_big_u64(stage_progress.data(), block_num);
        auto tgt{db::open_cursor(txn, domain)};
        mdbx::slice key{const_cast<char*>(stage_name), std::strlen(stage_name)};
        mdbx::slice value{db::to_slice(stage_progress)};
        tgt.upsert(key, value);
        tgt.close();
    }

}  // namespace

uint64_t get_stage_progress(mdbx::txn& txn, const char* stage_name) {
    return get_stage_data(txn, stage_name, silkworm::db::table::kSyncStageProgress);
}

void set_stage_progress(mdbx::txn& txn, const char* stage_name, uint64_t block_num) {
    set_stage_data(txn, stage_name, block_num, silkworm::db::table::kSyncStageProgress);
}

uint64_t get_stage_unwind(mdbx::txn& txn, const char* stage_name) {
    return get_stage_data(txn, stage_name, silkworm::db::table::kSyncStageUnwind);
}

void set_stage_unwind(mdbx::txn& txn, const char* stage_name, uint64_t block_num) {
    set_stage_data(txn, stage_name, block_num, silkworm::db::table::kSyncStageUnwind);
}

void clear_stage_unwind(mdbx::txn& txn, const char* stage_name) {
    set_stage_data(txn, stage_name, 0, silkworm::db::table::kSyncStageUnwind);
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
