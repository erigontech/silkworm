// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <ranges>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/db/datastore/snapshots/basic_queries.hpp>
#include <silkworm/db/datastore/snapshots/snapshot_repository_ro_access.hpp>

#include "../schema_config.hpp"
#include "txn_segment.hpp"

namespace silkworm::snapshots {

using TransactionFindByIdSegmentQuery = FindByIdSegmentQuery<TransactionSegmentWordDecoder, db::blocks::kTxnSegmentAndIdxNames>;
using TransactionFindByHashSegmentQuery = FindByHashSegmentQuery<TransactionSegmentWordDecoder, db::blocks::kTxnSegmentAndIdxNames>;

using TransactionRangeFromIdSegmentQuery = RangeFromIdSegmentQuery<TransactionSegmentWordDecoder, db::blocks::kTxnSegmentAndIdxNames>;
using TransactionRangeFromIdQuery = FindByTimestampMapQuery<TransactionRangeFromIdSegmentQuery>;

using TransactionPayloadRlpRangeFromIdSegmentQuery = RangeFromIdSegmentQuery<TransactionSegmentWordPayloadRlpDecoder<Bytes>, db::blocks::kTxnSegmentAndIdxNames>;
using TransactionPayloadRlpRangeFromIdQuery = FindByTimestampMapQuery<TransactionPayloadRlpRangeFromIdSegmentQuery>;

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

    std::optional<std::pair<BlockNum, TxnId>> exec(const Hash& hash) {
        // Lookup the entire txn to check that the retrieved txn hash matches (no way to know if key exists in MPHF)
        const auto cross_check_result = cross_check_query_.exec(hash);
        const auto result = cross_check_result ? index_.lookup_by_key(hash) : std::nullopt;
        if (!result) return std::nullopt;
        return std::pair<BlockNum, TxnId>{*result, cross_check_result->timestamp};
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

using TransactionBlockNumByTxnHashQuery = FindMapQuery<TransactionBlockNumByTxnHashSegmentQuery>;

}  // namespace silkworm::snapshots
