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

#include <ranges>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/db/datastore/snapshots/basic_queries.hpp>

#include "txn_snapshot.hpp"

namespace silkworm::snapshots {

using TransactionFindByIdQuery = FindByIdQuery<TransactionSnapshotReader>;
using TransactionFindByHashQuery = FindByHashQuery<TransactionSnapshotReader>;
using TransactionRangeFromIdQuery = RangeFromIdQuery<TransactionSnapshotReader>;
using TransactionPayloadRlpRangeFromIdQuery = RangeFromIdQuery<TransactionSnapshotPayloadRlpReader<Bytes>>;

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
        auto result = transaction ? index_.lookup_ordinal_by_hash(hash) : std::nullopt;
        return result;
    }

  private:
    const Index& index_;
    TransactionFindByHashQuery cross_check_query_;
};

template <std::ranges::view TBundlesView, class TBundle = typename std::ranges::iterator_t<TBundlesView>::value_type>
class TransactionBlockNumByTxnHashRepoQuery {
  public:
    explicit TransactionBlockNumByTxnHashRepoQuery(TBundlesView bundles)
        : bundles_(std::move(bundles)) {}

    std::optional<BlockNum> exec(const Hash& hash) {
        for (const TBundle& bundle_ptr : bundles_) {
            const auto& bundle = *bundle_ptr;
            const Snapshot& snapshot = bundle.txn_snapshot;
            const Index& idx_txn_hash = bundle.idx_txn_hash;
            const Index& idx_txn_hash_2_block = bundle.idx_txn_hash_2_block;

            TransactionFindByHashQuery cross_check_query{{snapshot, idx_txn_hash}};
            TransactionBlockNumByTxnHashQuery query{idx_txn_hash_2_block, cross_check_query};
            auto block_num = query.exec(hash);
            if (block_num) {
                return block_num;
            }
        }
        return std::nullopt;
    }

  private:
    TBundlesView bundles_;
};

}  // namespace silkworm::snapshots
