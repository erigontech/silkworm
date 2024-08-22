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

#include "header_snapshot_freezer.hpp"

#include <stdexcept>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/infra/common/log.hpp>

#include "header_snapshot.hpp"

namespace silkworm::db {

void HeaderSnapshotFreezer::copy(ROTxn& txn, const FreezerCommand& command, snapshots::SnapshotFileWriter& file_writer) const {
    BlockNumRange range = command.range;
    snapshots::HeaderSnapshotWriter writer{file_writer};
    auto out = writer.out();
    for (BlockNum i = range.first; i < range.second; i++) {
        auto value_opt = read_canonical_header(txn, i);
        if (!value_opt) throw std::runtime_error{"HeaderSnapshotFreezer::copy missing header for block " + std::to_string(i)};
        *out++ = *value_opt;
    }
}

void HeaderSnapshotFreezer::cleanup(RWTxn& txn, BlockNumRange range) const {
    for (BlockNum i = range.first, count = 1; i < range.second; i++, count++) {
        auto hash_opt = read_canonical_header_hash(txn, i);
        if (!hash_opt) continue;
        auto& hash = *hash_opt;

        delete_header(txn, i, hash);

        if ((count > 10000) && ((count % 10000) == 0)) {
            log::Debug("HeaderSnapshotFreezer") << "cleaned up until block " << i;
        }
    }
}

}  // namespace silkworm::db
