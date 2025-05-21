// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/datastore/domain_get_as_of_query.hpp>
#include <silkworm/db/datastore/domain_get_latest_query.hpp>
#include <silkworm/db/datastore/history_get_query.hpp>
#include <silkworm/db/datastore/kvdb/domain_queries.hpp>
#include <silkworm/db/datastore/snapshots/segment/kv_segment_reader.hpp>

#include "account_codecs.hpp"
#include "address_codecs.hpp"
#include "schema_config.hpp"

namespace silkworm::db::state {

using AccountsDomainKVSegmentReader = snapshots::segment::KVSegmentReader<AddressSnapshotsDecoder, AccountSnapshotsCodec>;

struct AccountsDomainGetLatestQuery : public datastore::DomainGetLatestQuery<
                                          AddressKVDBEncoder, AddressSnapshotsEncoder,
                                          AccountKVDBCodec, AccountSnapshotsCodec> {
    AccountsDomainGetLatestQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository,
        const snapshots::QueryCaches& query_caches)
        : datastore::DomainGetLatestQuery<
              AddressKVDBEncoder, AddressSnapshotsEncoder,
              AccountKVDBCodec, AccountSnapshotsCodec>{
              db::state::kDomainNameAccounts,
              database.domain(db::state::kDomainNameAccounts),
              tx,
              repository,
              query_caches,
          } {}
};

struct AccountsDomainPutQuery : public datastore::kvdb::DomainPutQuery<AddressKVDBEncoder, AccountKVDBCodec> {
    AccountsDomainPutQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::RWTxn& rw_tx)
        : datastore::kvdb::DomainPutQuery<AddressKVDBEncoder, AccountKVDBCodec>{
              rw_tx,
              database.domain(db::state::kDomainNameAccounts)} {}
};

struct AccountsDomainDeleteQuery : datastore::kvdb::DomainDeleteQuery<AddressKVDBEncoder, AccountKVDBCodec> {
    AccountsDomainDeleteQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::RWTxn& rw_tx)
        : datastore::kvdb::DomainDeleteQuery<AddressKVDBEncoder, AccountKVDBCodec>{
              rw_tx,
              database.domain(db::state::kDomainNameAccounts)} {}
};

using AccountsHistoryGetQuery = datastore::HistoryGetQuery<
    AddressKVDBEncoder, AddressSnapshotsEncoder,
    AccountKVDBCodec, AccountSnapshotsCodec,
    kHistorySegmentAndIdxNamesAccounts>;

using AccountsDomainGetAsOfQuery = datastore::DomainGetAsOfQuery<
    AddressKVDBEncoder, AddressSnapshotsEncoder,
    AccountKVDBCodec, AccountSnapshotsCodec,
    kHistorySegmentAndIdxNamesAccounts>;

}  // namespace silkworm::db::state
