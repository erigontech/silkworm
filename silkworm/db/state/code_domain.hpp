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

#include "address_codecs.hpp"

namespace silkworm::db::state {

using CodeDomainGetLatestQuery = datastore::DomainGetLatestQuery<
    AddressKVDBEncoder, AddressSnapshotsEncoder,
    datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>>;
using CodeDomainPutQuery = datastore::kvdb::DomainPutQuery<AddressKVDBEncoder, datastore::kvdb::RawEncoder<ByteView>>;
using CodeDomainDeleteQuery = datastore::kvdb::DomainDeleteQuery<AddressKVDBEncoder, datastore::kvdb::RawEncoder<ByteView>>;

using CodeDomainKVSegmentReader = snapshots::segment::KVSegmentReader<AddressSnapshotsDecoder, snapshots::RawDecoder<Bytes>>;

}  // namespace silkworm::db::state
