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

#include "stages.hpp"

#include <boost/endian/conversion.hpp>

namespace silkworm::db::stages {

uint64_t get_stage_progress(std::unique_ptr<lmdb::Transaction>& txn, const char* stage_name) {
    MDB_val key{std::strlen(stage_name), (void*)stage_name};
    auto data{txn->data_lookup(silkworm::db::table::kSyncStageProgress, &key)};
    if (!data.has_value()) return 0;
    return boost::endian::load_big_u64(data->c_str());
}

void set_stage_progress(std::unique_ptr<lmdb::Transaction>& txn, const char* stage_name, uint64_t block_num) {
    Bytes value{8, '\0'};
    boost::endian::store_big_u64(&value[0], block_num);

    MDB_val key{}, data{};
    key.mv_size = std::strlen(stage_name);
    key.mv_data = (void*)stage_name;
    data.mv_size = 8;
    data.mv_data = const_cast<uint8_t*>(value.data());

    lmdb::err_handler(txn->data_upsert(silkworm::db::table::kSyncStageProgress, &key, &data));
}

}  // namespace silkworm::db::stages
