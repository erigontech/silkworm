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

#include "stages.hpp"

#include <stdexcept>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/node/db/tables.hpp>

namespace silkworm::rpc::stages {

Task<BlockNum> get_sync_stage_progress(const core::rawdb::DatabaseReader& db_reader, const silkworm::Bytes& stage_key) {
    const auto kv_pair = co_await db_reader.get(db::table::kSyncStageProgressName, stage_key);
    const auto value = kv_pair.value;
    if (value.length() == 0) {
        co_return 0;
    }
    if (value.length() < 8) {
        throw std::runtime_error("data too short, expected 8 got " + std::to_string(value.length()));
    }
    BlockNum block_height = endian::load_big_u64(value.substr(0, 8).data());
    co_return block_height;
}

}  // namespace silkworm::rpc::stages
