// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/datastore/domain_get_as_of_query.hpp>
#include <silkworm/db/datastore/domain_get_latest_query.hpp>
#include <silkworm/db/datastore/history_get_query.hpp>
#include <silkworm/db/datastore/kvdb/domain_queries.hpp>
#include <silkworm/db/datastore/snapshots/common/raw_codec.hpp>
#include <silkworm/db/datastore/snapshots/segment/kv_segment_reader.hpp>

#include "schema_config.hpp"

namespace silkworm::db::state {

using CommitmentDomainKVSegmentReader = snapshots::segment::KVSegmentReader<snapshots::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>>;

struct CommitmentDomainGetLatestQuery : public datastore::DomainGetLatestQuery<
                                            datastore::kvdb::RawEncoder<ByteView>, snapshots::RawEncoder<ByteView>,
                                            datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>> {
    CommitmentDomainGetLatestQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : datastore::DomainGetLatestQuery<
              datastore::kvdb::RawEncoder<ByteView>, snapshots::RawEncoder<ByteView>,
              datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>>(
              db::state::kDomainNameCommitment,
              database.domain(db::state::kDomainNameCommitment),
              tx,
              repository) {}
};

struct CommitmentDomainPutQuery : public datastore::kvdb::DomainPutQuery<datastore::kvdb::RawEncoder<ByteView>, datastore::kvdb::RawEncoder<ByteView>> {
    CommitmentDomainPutQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::RWTxn& rw_tx)
        : datastore::kvdb::DomainPutQuery<datastore::kvdb::RawEncoder<ByteView>, datastore::kvdb::RawEncoder<ByteView>>{
              rw_tx,
              database.domain(db::state::kDomainNameCommitment)} {}
};

struct CommitmentDomainDeleteQuery : datastore::kvdb::DomainDeleteQuery<datastore::kvdb::RawEncoder<ByteView>, datastore::kvdb::RawEncoder<ByteView>> {
    CommitmentDomainDeleteQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::RWTxn& rw_tx)
        : datastore::kvdb::DomainDeleteQuery<datastore::kvdb::RawEncoder<ByteView>, datastore::kvdb::RawEncoder<ByteView>>{
              rw_tx,
              database.domain(db::state::kDomainNameCommitment)} {}
};

using CommitmentHistoryGetQuery = datastore::HistoryGetQuery<
    datastore::kvdb::RawEncoder<ByteView>, snapshots::RawEncoder<ByteView>,
    datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>,
    kHistorySegmentAndIdxNamesCommitment>;

using CommitmentDomainGetAsOfQuery = datastore::DomainGetAsOfQuery<
    datastore::kvdb::RawEncoder<ByteView>, snapshots::RawEncoder<ByteView>,
    datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>,
    kHistorySegmentAndIdxNamesCommitment>;

}  // namespace silkworm::db::state
