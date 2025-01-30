/*
   Copyright 2025 The Silkworm Authors

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
