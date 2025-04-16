// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/datastore/kvdb/inverted_index_put_query.hpp>
#include <silkworm/db/datastore/snapshots/common/raw_codec.hpp>
#include <silkworm/db/datastore/snapshots/segment/kv_segment_reader.hpp>

#include "address_codecs.hpp"
#include "hash_decoder.hpp"

namespace silkworm::db::state {

using LogTopicsInvertedIndexKVSegmentReader = snapshots::segment::KVSegmentReader<HashSnapshotsDecoder, snapshots::RawDecoder<Bytes>>;

using LogTopicsToInvertedIndexPutQuery = datastore::kvdb::InvertedIndexPutQuery<AddressKVDBEncoder>;

}  // namespace silkworm::db::state
