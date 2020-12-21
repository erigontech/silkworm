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

    uint64_t get_stage_progress(std::unique_ptr<lmdb::Transaction>& txn, const char* stage_name)
    {
        MDB_val key{std::strlen(stage_name), (void*)stage_name};
        auto data{txn->data_lookup(silkworm::db::table::kSyncStageProgress, &key)};
        if (!data.has_value()) return 0;
        return boost::endian::load_big_u64(data->c_str());
    }

    void set_stage_progress(std::unique_ptr<lmdb::Transaction>& txn, const char* stage_name, uint64_t block_num)
    {
        Bytes value{ '\0', sizeof(uint64_t) };
        boost::endian::store_big_u64(&value[0], block_num);
        db::Entry entry{ {(uint8_t*)(stage_name), std::strlen(stage_name)}, {value} };
        lmdb::err_handler(txn->data_upsert(silkworm::db::table::kSyncStageProgress, entry));
    }

}  // namespace silkworm::db::stages
