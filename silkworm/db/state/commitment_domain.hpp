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

#include <silkworm/db/datastore/kvdb/domain.hpp>
#include <silkworm/db/datastore/snapshots/common/raw_codec.hpp>
#include <silkworm/db/datastore/snapshots/segment/kv_segment_reader.hpp>

namespace silkworm::db::state {

using CommitmentDomainGetLatestQuery = datastore::kvdb::DomainGetLatestQuery<datastore::kvdb::RawEncoder<ByteView>, datastore::kvdb::RawDecoder<ByteView>>;
using CommitmentDomainPutQuery = datastore::kvdb::DomainPutQuery<datastore::kvdb::RawEncoder<ByteView>, datastore::kvdb::RawEncoder<ByteView>>;
using CommitmentDomainDeleteQuery = datastore::kvdb::DomainDeleteQuery<datastore::kvdb::RawEncoder<ByteView>, datastore::kvdb::RawEncoder<ByteView>>;

using CommitmentDomainKVSegmentReader = snapshots::segment::KVSegmentReader<snapshots::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>>;

}  // namespace silkworm::db::state
