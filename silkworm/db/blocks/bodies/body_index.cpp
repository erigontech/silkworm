// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "body_index.hpp"

#include <silkworm/db/datastore/snapshots/segment/seg/common/varint.hpp>

namespace silkworm::snapshots {

Bytes BodyIndex::KeyFactory::make(ByteView /*key_data*/, uint64_t i) {
    Bytes uint64_buffer;
    seg::varint::encode(uint64_buffer, i);
    return uint64_buffer;
}

}  // namespace silkworm::snapshots
