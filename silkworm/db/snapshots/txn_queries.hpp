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

#pragma once

#include <silkworm/core/common/bytes.hpp>

#include "basic_queries.hpp"
#include "txn_snapshot.hpp"

namespace silkworm::snapshots {

struct TransactionFindByIdQuery : public FindByIdQuery<TransactionSnapshotReader> {
    using FindByIdQuery<TransactionSnapshotReader>::FindByIdQuery;
};

struct TransactionFindByHashQuery : public FindByHashQuery<TransactionSnapshotReader> {
    using FindByHashQuery<TransactionSnapshotReader>::FindByHashQuery;
};

struct TransactionRangeFromIdQuery : public RangeFromIdQuery<TransactionSnapshotReader> {
    using RangeFromIdQuery<TransactionSnapshotReader>::RangeFromIdQuery;
};

struct TransactionPayloadRlpRangeFromIdQuery : public RangeFromIdQuery<TransactionSnapshotPayloadRlpReader<Bytes>> {
    using RangeFromIdQuery<TransactionSnapshotPayloadRlpReader<Bytes>>::RangeFromIdQuery;
};

class TransactionBlockNumByTxnHashQuery {
  public:
    TransactionBlockNumByTxnHashQuery(
        const Index& index,
        TransactionFindByHashQuery cross_check_query)
        : index_(index),
          cross_check_query_(cross_check_query) {}

    std::optional<BlockNum> exec(const Hash& hash) {
        // Lookup the entire txn to check that the retrieved txn hash matches (no way to know if key exists in MPHF)
        const auto transaction = cross_check_query_.exec(hash);
        auto result = transaction ? index_.lookup_by_hash(hash) : std::nullopt;
        return result;
    }

  private:
    const Index& index_;
    TransactionFindByHashQuery cross_check_query_;
};

}  // namespace silkworm::snapshots
