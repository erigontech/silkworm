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

#include "../schema_config.hpp"
#include "txn_segment.hpp"

namespace silkworm::snapshots {

using TransactionFindByIdSegmentQuery = FindByIdSegmentQuery<TransactionSegmentReader>;
using TransactionFindByHashSegmentQuery = FindByHashSegmentQuery<TransactionSegmentReader>;
using TransactionRangeFromIdSegmentQuery = RangeFromIdSegmentQuery<TransactionSegmentReader>;
using TransactionPayloadRlpRangeFromIdSegmentQuery = RangeFromIdSegmentQuery<TransactionSegmentPayloadRlpReader<Bytes>>;

class TransactionBlockNumByTxnHashSegmentQuery {
  public:
    TransactionBlockNumByTxnHashSegmentQuery(
        const rec_split::AccessorIndex& index,
        TransactionFindByHashSegmentQuery cross_check_query)
        : index_(index),
          cross_check_query_(cross_check_query) {}

    explicit TransactionBlockNumByTxnHashSegmentQuery(
        const SnapshotBundle& bundle)
        : TransactionBlockNumByTxnHashSegmentQuery{
              make(db::blocks::BundleDataRef{*bundle})} {}

    std::optional<BlockNum> exec(const Hash& hash) {
        // Lookup the entire txn to check that the retrieved txn hash matches (no way to know if key exists in MPHF)
        const auto transaction = cross_check_query_.exec(hash);
        auto result = transaction ? index_.lookup_ordinal_by_hash(hash) : std::nullopt;
        return result;
    }

    static TransactionBlockNumByTxnHashSegmentQuery make(db::blocks::BundleDataRef bundle) {
        TransactionFindByHashSegmentQuery cross_check_query{
            SegmentAndAccessorIndex{
                bundle.txn_segment(),
                bundle.idx_txn_hash(),
            },
        };
        return {bundle.idx_txn_hash_2_block(), cross_check_query};
    }

  private:
    const rec_split::AccessorIndex& index_;
    TransactionFindByHashSegmentQuery cross_check_query_;
};

class TransactionBlockNumByTxnHashQuery {
  public:
    // TODO: use a sub-interface of SnapshotRepository
    explicit TransactionBlockNumByTxnHashQuery(SnapshotRepository& repository)
        : repository_{repository} {}

    std::optional<BlockNum> exec(const Hash& hash) {
        for (const auto& bundle_ptr : repository_.view_bundles_reverse()) {
            TransactionBlockNumByTxnHashSegmentQuery query{*bundle_ptr};
            auto block_num = query.exec(hash);
            if (block_num) {
                return block_num;
            }
        }
        return std::nullopt;
    }

  private:
    SnapshotRepository& repository_;
};

}  // namespace silkworm::snapshots
