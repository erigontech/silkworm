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

#include <stdexcept>

#include <silkworm/db/datastore/kvdb/domain.hpp>
#include <silkworm/db/datastore/snapshots/segment/kv_segment_reader.hpp>
#include <silkworm/db/datastore/snapshots/segment/seg/common/varint.hpp>

namespace silkworm::db::state {

using ReceiptsDomainGetLatestQuery = datastore::kvdb::DomainGetLatestQuery<datastore::kvdb::RawEncoder<ByteView>, datastore::kvdb::RawDecoder<ByteView>>;
using ReceiptsDomainPutQuery = datastore::kvdb::DomainPutQuery<datastore::kvdb::RawEncoder<ByteView>, datastore::kvdb::RawEncoder<ByteView>>;
using ReceiptsDomainDeleteQuery = datastore::kvdb::DomainDeleteQuery<datastore::kvdb::RawEncoder<ByteView>, datastore::kvdb::RawEncoder<ByteView>>;

enum class ReceiptsDomainKey : uint8_t {
    kCumulativeGasUsedInBlockKey = 0,
    kCumulativeBlobGasUsedInBlockKey = 1,
    kFirstLogIndexKey = 2,
};

struct ReceiptsDomainKeyDecoder : public snapshots::Decoder {
    ReceiptsDomainKey value{};
    ~ReceiptsDomainKeyDecoder() override = default;
    void decode_word(ByteView word) override {
        if (word.empty())
            throw std::runtime_error{"ReceiptsDomainKeyDecoder failed to decode an empty word"};
        value = static_cast<ReceiptsDomainKey>(word[0]);
    }
};

static_assert(snapshots::DecoderConcept<ReceiptsDomainKeyDecoder>);

struct VarintDecoder : public snapshots::Decoder {
    uint64_t value{};
    ~VarintDecoder() override = default;
    void decode_word(ByteView word) override {
        auto value_opt = snapshots::seg::varint::decode(word);
        if (!value_opt)
            throw std::runtime_error{"VarintDecoder failed to decode"};
        value = *value_opt;
    }
};

static_assert(snapshots::DecoderConcept<VarintDecoder>);

using ReceiptsDomainKVSegmentReader = snapshots::segment::KVSegmentReader<ReceiptsDomainKeyDecoder, VarintDecoder>;

}  // namespace silkworm::db::state
