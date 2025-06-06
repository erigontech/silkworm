// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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

enum class ReceiptsDomainKey : uint8_t {
    kCumulativeGasUsedInBlockKey = 0,
    kCumulativeBlobGasUsedInBlockKey = 1,
    kFirstLogIndexKey = 2,
};

struct ReceiptsDomainKeySnapshotsDecoder : public snapshots::Decoder {
    ReceiptsDomainKey value{};
    ~ReceiptsDomainKeySnapshotsDecoder() override = default;
    void decode_word(Word& word) override {
        const ByteView word_view = word;
        if (word_view.empty())
            throw std::runtime_error{"ReceiptsDomainKeySnapshotsDecoder failed to decode an empty word"};
        value = static_cast<ReceiptsDomainKey>(word_view[0]);
    }
};

static_assert(snapshots::DecoderConcept<ReceiptsDomainKeySnapshotsDecoder>);

struct VarintSnapshotsDecoder : public snapshots::Decoder {
    uint64_t value{};
    ~VarintSnapshotsDecoder() override = default;
    void decode_word(Word& word) override {
        ByteView word_view = word;
        auto value_opt = snapshots::seg::varint::decode(word_view);
        if (!value_opt)
            throw std::runtime_error{"VarintSnapshotsDecoder failed to decode"};
        value = *value_opt;
    }
};

static_assert(snapshots::DecoderConcept<VarintSnapshotsDecoder>);

struct VarintSnapshotEncoder : public snapshots::Encoder {
    Bytes& output_buffer;
    uint64_t value{};
    VarintSnapshotEncoder(Bytes& output, uint64_t val) : output_buffer(output), value{val} {}
    ~VarintSnapshotEncoder() override = default;
    ByteView encode_word() override {
        return snapshots::seg::varint::encode(output_buffer, value);
    }
};

static_assert(snapshots::EncoderConcept<VarintSnapshotEncoder>);

using ReceiptsDomainKVSegmentReader = snapshots::segment::KVSegmentReader<ReceiptsDomainKeySnapshotsDecoder, VarintSnapshotsDecoder>;

struct ReceiptsDomainGetLatestQuery : public datastore::DomainGetLatestQuery<
                                          datastore::kvdb::RawEncoder<ByteView>, snapshots::RawEncoder<ByteView>,
                                          datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>> {
    ReceiptsDomainGetLatestQuery(
        const datastore::kvdb::DatabaseRef& database,
        datastore::kvdb::ROTxn& tx,
        const snapshots::SnapshotRepositoryROAccess& repository,
        const snapshots::QueryCaches& query_caches)
        : datastore::DomainGetLatestQuery<
              datastore::kvdb::RawEncoder<ByteView>, snapshots::RawEncoder<ByteView>,
              datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>>{
              db::state::kDomainNameReceipts,
              database.domain(db::state::kDomainNameReceipts),
              tx,
              repository,
              query_caches,
          } {}
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

using ReceiptsHistoryGetQuery = datastore::HistoryGetQuery<
    datastore::kvdb::RawEncoder<ByteView>, snapshots::RawEncoder<ByteView>,
    datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>,
    kHistorySegmentAndIdxNamesReceipts>;

using ReceiptsDomainGetAsOfQuery = datastore::DomainGetAsOfQuery<
    datastore::kvdb::RawEncoder<ByteView>, snapshots::RawEncoder<ByteView>,
    datastore::kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>,
    kHistorySegmentAndIdxNamesReceipts>;

}  // namespace silkworm::db::state
