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

#include "account_codecs.hpp"
#include "address_codecs.hpp"
#include "schema_config.hpp"

namespace silkworm::db::state {

using AccountsDomainGetLatestQueryBase = datastore::DomainGetLatestQuery<
    AddressKVDBEncoder, AddressSnapshotsEncoder,
    AccountKVDBCodec, AccountSnapshotsCodec>;

struct AccountsDomainGetLatestQuery : public AccountsDomainGetLatestQueryBase {
    AccountsDomainGetLatestQuery(
        datastore::kvdb::DatabaseRef database,
        datastore::kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : AccountsDomainGetLatestQueryBase{
              db::state::kDomainNameAccounts,
              std::move(database),
              tx,
              repository,
          } {}
};

using AccountsDomainPutQuery = datastore::kvdb::DomainPutQuery<AddressKVDBEncoder, AccountKVDBCodec>;
using AccountsDomainDeleteQuery = datastore::kvdb::DomainDeleteQuery<AddressKVDBEncoder, AccountKVDBCodec>;

using AccountsDomainKVSegmentReader = snapshots::segment::KVSegmentReader<AddressSnapshotsDecoder, AccountSnapshotsCodec>;

}  // namespace silkworm::db::state
