/*
   Copyright 2024 The Silkworm Authors

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

#include "head_info.hpp"

#include <gsl/util>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::db {

HeadInfo read_head_info(ROTxn& txn) {
    HeadInfo head_info;

    BlockNum head_height = db::stages::read_stage_progress(txn, db::stages::kBlockBodiesKey);
    head_info.block_num = head_height;

    auto head_hash = db::read_canonical_hash(txn, head_height);
    if (head_hash) {
        head_info.hash = head_hash.value();
    } else {
        log::Warning("db::HeadInfo") << "canonical hash at height " << std::to_string(head_height) << " not found in db";
        return head_info;
    }

    auto head_total_difficulty = db::read_total_difficulty(txn, head_height, *head_hash);
    if (head_total_difficulty) {
        head_info.total_difficulty = head_total_difficulty.value();
    } else {
        log::Warning("db::HeadInfo") << "total difficulty of canonical hash at height " << std::to_string(head_height) << " not found in db";
    }

    return head_info;
}

HeadInfo read_head_info(db::ROAccess db_access) {
    auto txn = db_access.start_ro_tx();
    [[maybe_unused]] auto _ = gsl::finally([&txn] { txn.abort(); });

    return read_head_info(txn);
}

}  // namespace silkworm::db
