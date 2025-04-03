// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/datastore/domain_get_as_of_query.hpp>
#include <silkworm/db/datastore/domain_get_latest_query.hpp>
#include <silkworm/db/datastore/history_get_query.hpp>
#include <silkworm/db/datastore/kvdb/domain_queries.hpp>
#include <silkworm/db/datastore/snapshots/segment/kv_segment_reader.hpp>

#include "schema_config.hpp"
#include "storage_codecs.hpp"

namespace silkworm::db::state {

using StorageDomainKVSegmentReader = snapshots::segment::KVSegmentReader<StorageAddressAndLocationSnapshotsCodec, Bytes32SnapshotsCodec>;

struct StorageDomainGetLatestQuery : public datastore::DomainGetLatestQuery<
                                         StorageAddressAndLocationKVDBEncoder, StorageAddressAndLocationSnapshotsCodec,
                                         PackedBytes32KVDBCodec, PackedBytes32SnapshotsCodec> {
    StorageDomainGetLatestQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : datastore::DomainGetLatestQuery<
              StorageAddressAndLocationKVDBEncoder, StorageAddressAndLocationSnapshotsCodec,
              PackedBytes32KVDBCodec, PackedBytes32SnapshotsCodec>(
              db::state::kDomainNameStorage,
              database.domain(db::state::kDomainNameStorage),
              tx,
              repository) {}
};

struct StorageDomainPutQuery : public datastore::kvdb::DomainPutQuery<StorageAddressAndLocationKVDBEncoder, PackedBytes32KVDBCodec> {
    StorageDomainPutQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::RWTxn& rw_tx)
        : datastore::kvdb::DomainPutQuery<StorageAddressAndLocationKVDBEncoder, PackedBytes32KVDBCodec>{
              rw_tx,
              database.domain(db::state::kDomainNameStorage)} {}
};

struct StorageDomainDeleteQuery : datastore::kvdb::DomainDeleteQuery<StorageAddressAndLocationKVDBEncoder, PackedBytes32KVDBCodec> {
    StorageDomainDeleteQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::RWTxn& rw_tx)
        : datastore::kvdb::DomainDeleteQuery<StorageAddressAndLocationKVDBEncoder, PackedBytes32KVDBCodec>{
              rw_tx,
              database.domain(db::state::kDomainNameStorage)} {}
};

using StorageHistoryGetQuery = datastore::HistoryGetQuery<
    StorageAddressAndLocationKVDBEncoder, StorageAddressAndLocationSnapshotsCodec,
    PackedBytes32KVDBCodec, PackedBytes32SnapshotsCodec,
    kHistorySegmentAndIdxNamesStorage>;

using StorageDomainGetAsOfQuery = datastore::DomainGetAsOfQuery<
    StorageAddressAndLocationKVDBEncoder, StorageAddressAndLocationSnapshotsCodec,
    PackedBytes32KVDBCodec, PackedBytes32SnapshotsCodec,
    kHistorySegmentAndIdxNamesStorage>;

}  // namespace silkworm::db::state
