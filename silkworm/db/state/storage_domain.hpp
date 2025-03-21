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
