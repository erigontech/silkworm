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
#include <silkworm/db/datastore/snapshots/common/raw_codec.hpp>
#include <silkworm/db/datastore/snapshots/segment/kv_segment_reader.hpp>

#include "schema_config.hpp"

namespace silkworm::db::state {

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

using CommitmentDomainKVSegmentReader = snapshots::segment::KVSegmentReader<snapshots::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>>;

}  // namespace silkworm::db::state
