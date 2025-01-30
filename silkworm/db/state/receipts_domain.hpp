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

#include <silkworm/db/datastore/domain_get_as_of_query.hpp>
#include <silkworm/db/datastore/domain_get_latest_query.hpp>
#include <silkworm/db/datastore/history_get_query.hpp>
#include <silkworm/db/datastore/kvdb/domain_queries.hpp>
#include <silkworm/db/datastore/snapshots/segment/kv_segment_reader.hpp>
#include <silkworm/db/datastore/snapshots/segment/seg/common/varint.hpp>

#include "schema_config.hpp"

namespace silkworm::db::state {

struct ReceiptsDomainGetLatestQuery : public datastore::DomainGetLatestQuery<
                                          datastore::kvdb::RawEncoder<ByteView>, snapshots::RawEncoder<ByteView>,
                                          datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>> {
    ReceiptsDomainGetLatestQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : datastore::DomainGetLatestQuery<
              datastore::kvdb::RawEncoder<ByteView>, snapshots::RawEncoder<ByteView>,
              datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>>(
              db::state::kDomainNameReceipts,
              database.domain(db::state::kDomainNameReceipts),
              tx,
              repository) {}
};

struct ReceiptsDomainPutQuery : public datastore::kvdb::DomainPutQuery<datastore::kvdb::RawEncoder<ByteView>, datastore::kvdb::RawEncoder<ByteView>> {
    ReceiptsDomainPutQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::RWTxn& rw_tx)
        : datastore::kvdb::DomainPutQuery<datastore::kvdb::RawEncoder<ByteView>, datastore::kvdb::RawEncoder<ByteView>>{
              rw_tx,
              database.domain(db::state::kDomainNameReceipts)} {}
};

struct ReceiptsDomainDeleteQuery : datastore::kvdb::DomainDeleteQuery<datastore::kvdb::RawEncoder<ByteView>, datastore::kvdb::RawEncoder<ByteView>> {
    ReceiptsDomainDeleteQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::RWTxn& rw_tx)
        : datastore::kvdb::DomainDeleteQuery<datastore::kvdb::RawEncoder<ByteView>, datastore::kvdb::RawEncoder<ByteView>>{
              rw_tx,
              database.domain(db::state::kDomainNameReceipts)} {}
};

enum class ReceiptsDomainKey : uint8_t {
    kCumulativeGasUsedInBlockKey = 0,
    kCumulativeBlobGasUsedInBlockKey = 1,
    kFirstLogIndexKey = 2,
};

struct ReceiptsDomainKeySnapshotsDecoder : public snapshots::Decoder {
    ReceiptsDomainKey value{};
    ~ReceiptsDomainKeySnapshotsDecoder() override = default;
    void decode_word(ByteView word) override {
        if (word.empty())
            throw std::runtime_error{"ReceiptsDomainKeySnapshotsDecoder failed to decode an empty word"};
        value = static_cast<ReceiptsDomainKey>(word[0]);
    }
};

static_assert(snapshots::DecoderConcept<ReceiptsDomainKeySnapshotsDecoder>);

struct VarintSnapshotsDecoder : public snapshots::Decoder {
    uint64_t value{};
    ~VarintSnapshotsDecoder() override = default;
    void decode_word(ByteView word) override {
        auto value_opt = snapshots::seg::varint::decode(word);
        if (!value_opt)
            throw std::runtime_error{"VarintSnapshotsDecoder failed to decode"};
        value = *value_opt;
    }
};

static_assert(snapshots::DecoderConcept<VarintSnapshotsDecoder>);

using ReceiptsDomainKVSegmentReader = snapshots::segment::KVSegmentReader<ReceiptsDomainKeySnapshotsDecoder, VarintSnapshotsDecoder>;

using ReceiptsDomainGetLatestQueryBase = datastore::DomainGetLatestQuery<
    datastore::kvdb::RawEncoder<ByteView>, snapshots::RawEncoder<ByteView>,
    datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>>;

struct ReceiptsDomainGetLatestQuery : public ReceiptsDomainGetLatestQueryBase {
    ReceiptsDomainGetLatestQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : ReceiptsDomainGetLatestQueryBase{
              db::state::kDomainNameReceipts,
              database,
              tx,
              repository,
          } {}
};

using ReceiptsDomainPutQuery = datastore::kvdb::DomainPutQuery<datastore::kvdb::RawEncoder<ByteView>, datastore::kvdb::RawEncoder<ByteView>>;
using ReceiptsDomainDeleteQuery = datastore::kvdb::DomainDeleteQuery<datastore::kvdb::RawEncoder<ByteView>, datastore::kvdb::RawEncoder<ByteView>>;

using ReceiptsHistoryGetQuery = datastore::HistoryGetQuery<
    datastore::kvdb::RawEncoder<ByteView>, snapshots::RawEncoder<ByteView>,
    datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>,
    &kHistorySegmentAndIdxNamesReceipts>;

using ReceiptsDomainGetAsOfQuery = datastore::DomainGetAsOfQuery<
    datastore::kvdb::RawEncoder<ByteView>, snapshots::RawEncoder<ByteView>,
    datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>,
    &kHistorySegmentAndIdxNamesReceipts>;

}  // namespace silkworm::db::state
