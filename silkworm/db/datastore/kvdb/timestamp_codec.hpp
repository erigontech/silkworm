// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "big_endian_codec.hpp"

namespace silkworm::datastore::kvdb {

using TimestampEncoder = BigEndianU64Codec;
using TimestampDecoder = BigEndianU64Codec;

}  // namespace silkworm::datastore::kvdb
