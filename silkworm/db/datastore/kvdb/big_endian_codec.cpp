// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "big_endian_codec.hpp"

#include <silkworm/core/common/endian.hpp>

namespace silkworm::datastore::kvdb {

Slice BigEndianU64Codec::encode() {
    data.resize(sizeof(uint64_t), 0);
    endian::store_big_u64(data.data(), value);
    return to_slice(data);
}

void BigEndianU64Codec::decode(Slice slice) {
    SILKWORM_ASSERT(slice.size() >= sizeof(uint64_t));
    value = endian::load_big_u64(static_cast<uint8_t*>(slice.data()));
}

}  // namespace silkworm::datastore::kvdb
