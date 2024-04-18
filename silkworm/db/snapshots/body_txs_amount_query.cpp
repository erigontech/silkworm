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

#include "body_txs_amount_query.hpp"

#include <stdexcept>

#include "body_snapshot.hpp"

namespace silkworm::snapshots {

BodyTxsAmountQuery::Result BodyTxsAmountQuery::exec() {
    auto path = snapshot_.path();
    uint64_t first_tx_id{0}, last_tx_id{0}, last_txs_amount{0};
    BlockNum number = path.block_from();

    BodySnapshotReader reader{snapshot_};
    for (auto& body : reader) {
        if (number == path.block_from()) {
            first_tx_id = body.base_txn_id;
        }
        if (number == path.block_to() - 1) {
            last_tx_id = body.base_txn_id;
            last_txs_amount = body.txn_count;
        }
        number++;
    }

    if ((first_tx_id == 0) && (last_tx_id == 0)) {
        throw std::runtime_error("BodyTxsAmountQuery empty body snapshot: " + path.path().string());
    }

    uint64_t count = last_tx_id + last_txs_amount - first_tx_id;

    return Result{
        first_tx_id,
        count,
    };
}

}  // namespace silkworm::snapshots
