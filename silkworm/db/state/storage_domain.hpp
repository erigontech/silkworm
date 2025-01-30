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

#include <silkworm/db/datastore/domain_get_latest_query.hpp>
#include <silkworm/db/datastore/kvdb/domain_queries.hpp>
#include <silkworm/db/datastore/snapshots/segment/kv_segment_reader.hpp>

#include "schema_config.hpp"
#include "storage_codecs.hpp"

namespace silkworm::db::state {

struct StorageDomainGetLatestQuery : public datastore::DomainGetLatestQuery<
                                         StorageAddressAndLocationKVDBEncoder, StorageAddressAndLocationSnapshotsCodec,
                                         Bytes32KVDBCodec, Bytes32SnapshotsCodec> {
    StorageDomainGetLatestQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : datastore::DomainGetLatestQuery<
              StorageAddressAndLocationKVDBEncoder, StorageAddressAndLocationSnapshotsCodec,
              Bytes32KVDBCodec, Bytes32SnapshotsCodec>(
              db::state::kDomainNameStorage,
              database.domain(db::state::kDomainNameStorage),
              tx,
              repository) {}
};

struct StorageDomainPutQuery : public datastore::kvdb::DomainPutQuery<StorageAddressAndLocationKVDBEncoder, Bytes32KVDBCodec> {
    StorageDomainPutQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::RWTxn& rw_tx)
        : datastore::kvdb::DomainPutQuery<StorageAddressAndLocationKVDBEncoder, Bytes32KVDBCodec>{
              rw_tx,
              database.domain(db::state::kDomainNameStorage)} {}
};

struct StorageDomainDeleteQuery : datastore::kvdb::DomainDeleteQuery<StorageAddressAndLocationKVDBEncoder, Bytes32KVDBCodec> {
    StorageDomainDeleteQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::RWTxn& rw_tx)
        : datastore::kvdb::DomainDeleteQuery<StorageAddressAndLocationKVDBEncoder, Bytes32KVDBCodec>{
              rw_tx,
              database.domain(db::state::kDomainNameStorage)} {}
};

using StorageDomainKVSegmentReader = snapshots::segment::KVSegmentReader<StorageAddressAndLocationSnapshotsCodec, Bytes32SnapshotsCodec>;

}  // namespace silkworm::db::state
