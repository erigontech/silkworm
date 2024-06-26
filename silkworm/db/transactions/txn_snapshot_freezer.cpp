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

#include "txn_snapshot_freezer.hpp"

#include <stdexcept>

#include <silkworm/db/access_layer.hpp>

#include "txn_snapshot.hpp"

namespace silkworm::db {

void TransactionSnapshotFreezer::copy(ROTxn& txn, BlockNumRange range, snapshots::SnapshotFileWriter& file_writer) const {
    snapshots::TransactionSnapshotWriter writer{file_writer};
    auto out = writer.out();
    auto system_tx = snapshots::empty_system_tx();

    for (BlockNum i = range.first; i < range.second; i++) {
        BlockBody body;
        bool found = read_canonical_body(txn, i, /* read_senders = */ true, body);
        if (!found) throw std::runtime_error{"TransactionSnapshotFreezer::copy missing body for block " + std::to_string(i)};

        *out++ = system_tx;
        for (auto& value : body.transactions) {
            *out++ = value;
        }
        *out++ = system_tx;
    }
}

}  // namespace silkworm::db
