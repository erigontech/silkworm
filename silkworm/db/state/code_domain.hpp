// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/datastore/domain_get_as_of_query.hpp>
#include <silkworm/db/datastore/domain_get_latest_query.hpp>
#include <silkworm/db/datastore/history_get_query.hpp>
#include <silkworm/db/datastore/kvdb/domain_queries.hpp>
#include <silkworm/db/datastore/snapshots/common/raw_codec.hpp>
#include <silkworm/db/datastore/snapshots/segment/kv_segment_reader.hpp>

#include "address_codecs.hpp"
#include "schema_config.hpp"

namespace silkworm::db::state {

using CodeDomainKVSegmentReader = snapshots::segment::KVSegmentReader<AddressSnapshotsDecoder, snapshots::RawDecoder<Bytes>>;

struct CodeDomainGetLatestQuery : public datastore::DomainGetLatestQuery<
                                      AddressKVDBEncoder, AddressSnapshotsEncoder,
                                      datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>> {
    CodeDomainGetLatestQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : datastore::DomainGetLatestQuery<
              AddressKVDBEncoder, AddressSnapshotsEncoder,
              datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>>(
              db::state::kDomainNameCode,
              database.domain(db::state::kDomainNameCode),
              tx,
              repository) {}
};

struct CodeDomainPutQuery : public datastore::kvdb::DomainPutQuery<AddressKVDBEncoder, datastore::kvdb::RawEncoder<ByteView>> {
    CodeDomainPutQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::RWTxn& rw_tx)
        : datastore::kvdb::DomainPutQuery<AddressKVDBEncoder, datastore::kvdb::RawEncoder<ByteView>>{
              rw_tx,
              database.domain(db::state::kDomainNameCode)} {}
};

struct CodeDomainDeleteQuery : datastore::kvdb::DomainDeleteQuery<AddressKVDBEncoder, datastore::kvdb::RawEncoder<ByteView>> {
    CodeDomainDeleteQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::RWTxn& rw_tx)
        : datastore::kvdb::DomainDeleteQuery<AddressKVDBEncoder, datastore::kvdb::RawEncoder<ByteView>>{
              rw_tx,
              database.domain(db::state::kDomainNameCode)} {}
};

using CodeHistoryGetQuery = datastore::HistoryGetQuery<
    AddressKVDBEncoder, AddressSnapshotsEncoder,
    datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>,
    kHistorySegmentAndIdxNamesCode>;

using CodeDomainGetAsOfQuery = datastore::DomainGetAsOfQuery<
    AddressKVDBEncoder, AddressSnapshotsEncoder,
    datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>,
    kHistorySegmentAndIdxNamesCode>;

}  // namespace silkworm::db::state
