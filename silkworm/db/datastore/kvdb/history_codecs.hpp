// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../common/timestamp.hpp"
#include "kvts_codec.hpp"
#include "timestamp_codec.hpp"

namespace silkworm::datastore::kvdb {

template <EncoderConcept TEncoder>
using HistoryKeyEncoder = KVTSKeyEncoder<TEncoder, TimestampEncoder>;

template <EncoderConcept TEncoder>
using HistoryValueEncoder = KVTSValueEncoder<TEncoder, TimestampEncoder>;

template <DecoderConcept TDecoder>
using HistoryKeyDecoder = KVTSKeyDecoder<TDecoder, TimestampDecoder, sizeof(Timestamp)>;

template <DecoderConcept TDecoder>
using HistoryValueDecoder = KVTSValueDecoder<TDecoder, TimestampDecoder, sizeof(Timestamp)>;

}  // namespace silkworm::datastore::kvdb
