// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "local_transaction.hpp"

#include <map>
#include <string_view>
#include <vector>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/chain/local_chain_storage.hpp>
#include <silkworm/db/datastore/common/ranges/vector_from_range.hpp>
#include <silkworm/db/datastore/domain_get_as_of_query.hpp>
#include <silkworm/db/datastore/domain_get_latest_query.hpp>
#include <silkworm/db/datastore/domain_range_as_of_query.hpp>
#include <silkworm/db/datastore/history_get_query.hpp>
#include <silkworm/db/datastore/history_range_in_period_query.hpp>
#include <silkworm/db/datastore/inverted_index_range_by_key_query.hpp>
#include <silkworm/db/datastore/kvdb/raw_codec.hpp>
#include <silkworm/db/datastore/snapshots/common/raw_codec.hpp>
#include <silkworm/db/kv/txn_num.hpp>
#include <silkworm/db/tables.hpp>

#include "as_datastore_ts_range.hpp"

namespace silkworm::db::kv::api {

using namespace silkworm::datastore;

static const std::map<std::string_view, EntityName> kTable2EntityNames{
    {table::kAccountDomain, state::kDomainNameAccounts},
    {table::kStorageDomain, state::kDomainNameStorage},
    {table::kCodeDomain, state::kDomainNameCode},
    {table::kCommitmentDomain, state::kDomainNameCommitment},
    {table::kReceiptDomain, state::kDomainNameReceipts},

    {table::kAccountsHistoryIdx, state::kDomainNameAccounts},
    {table::kStorageHistoryIdx, state::kDomainNameStorage},
    {table::kCodeHistoryIdx, state::kDomainNameCode},
    {table::kCommitmentHistoryIdx, state::kDomainNameCommitment},
    {table::kReceiptHistoryIdx, state::kDomainNameReceipts},
    {table::kTracesFromIdx, state::kInvIdxNameTracesFrom},
    {table::kTracesToIdx, state::kInvIdxNameTracesTo},
    {table::kLogAddrIdx, state::kInvIdxNameLogAddress},
    {table::kLogTopicIdx, state::kInvIdxNameLogTopics},
};

using RawDomainGetLatestQuery = DomainGetLatestQuery<
    kvdb::RawEncoder<ByteView>, snapshots::RawEncoder<ByteView>,
    kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>>;

template <const snapshots::SegmentAndAccessorIndexNames& history_segment_names>
using RawDomainGetAsOfQuery = DomainGetAsOfQuery<
    kvdb::RawEncoder<ByteView>, snapshots::RawEncoder<ByteView>,
    kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>,
    history_segment_names>;
using AccountsDomainGetAsOfQuery = RawDomainGetAsOfQuery<state::kHistorySegmentAndIdxNamesAccounts>;
using StorageDomainGetAsOfQuery = RawDomainGetAsOfQuery<state::kHistorySegmentAndIdxNamesStorage>;
using CodeDomainGetAsOfQuery = RawDomainGetAsOfQuery<state::kHistorySegmentAndIdxNamesCode>;
using CommitmentDomainGetAsOfQuery = RawDomainGetAsOfQuery<state::kHistorySegmentAndIdxNamesCommitment>;
using ReceiptsDomainGetAsOfQuery = RawDomainGetAsOfQuery<state::kHistorySegmentAndIdxNamesReceipts>;

template <const snapshots::SegmentAndAccessorIndexNames& history_segment_names>
using RawHistoryGetQuery = HistoryGetQuery<
    kvdb::RawEncoder<ByteView>, snapshots::RawEncoder<ByteView>,
    kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>,
    history_segment_names>;
using AccountsHistoryGetQuery = RawHistoryGetQuery<state::kHistorySegmentAndIdxNamesAccounts>;
using StorageHistoryGetQuery = RawHistoryGetQuery<state::kHistorySegmentAndIdxNamesStorage>;
using CodeHistoryGetQuery = RawHistoryGetQuery<state::kHistorySegmentAndIdxNamesCode>;
using CommitmentHistoryGetQuery = RawHistoryGetQuery<state::kHistorySegmentAndIdxNamesCommitment>;
using ReceiptsHistoryGetQuery = RawHistoryGetQuery<state::kHistorySegmentAndIdxNamesReceipts>;

using RawInvertedIndexRangeByKeyQuery = InvertedIndexRangeByKeyQuery<
    kvdb::RawEncoder<Bytes>, snapshots::RawEncoder<Bytes>>;  // TODO(canepat) try ByteView
using RawInvertedIndexRangeByKeyQueryResult = InvertedIndexRangeByKeyQueryResult<
    kvdb::RawEncoder<Bytes>, snapshots::RawEncoder<Bytes>>;

using RawHistoryRangeInPeriodQuery = HistoryRangeInPeriodQuery<
    kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>, kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>>;
using RawHistoryRangeInPeriodQueryResult = HistoryRangeInPeriodQueryResult<
    kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>, kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>>;

using RawDomainRangeAsOfQuery = DomainRangeAsOfQuery<
    kvdb::RawEncoder<Bytes>, snapshots::RawEncoder<Bytes>,
    kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>,
    kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>>;
using RawDomainRangeAsOfQueryResult = DomainRangeAsOfQueryResult<
    kvdb::RawEncoder<Bytes>, snapshots::RawEncoder<Bytes>,
    kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>,
    kvdb::RawDecoder<Bytes>, snapshots::RawDecoder<Bytes>>;

Task<void> LocalTransaction::open() {
    co_return;
}

Task<std::shared_ptr<Cursor>> LocalTransaction::cursor(std::string_view table) {
    co_return co_await get_cursor(table, false);
}

Task<std::shared_ptr<CursorDupSort>> LocalTransaction::cursor_dup_sort(std::string_view table) {
    co_return co_await get_cursor(table, true);
}

Task<void> LocalTransaction::close() {
    cursors_.clear();
    co_return;
}

Task<std::shared_ptr<CursorDupSort>> LocalTransaction::get_cursor(std::string_view table_view, bool is_cursor_dup_sort) {
    std::string table{table_view};
    if (is_cursor_dup_sort) {
        auto cursor_it = dup_cursors_.find(table);
        if (cursor_it != dup_cursors_.end()) {
            co_return cursor_it->second;
        }
    } else {
        auto cursor_it = cursors_.find(table);
        if (cursor_it != cursors_.end()) {
            co_return cursor_it->second;
        }
    }
    auto cursor = std::make_shared<LocalCursor>(tx_, ++last_cursor_id_);
    co_await cursor->open_cursor(table, is_cursor_dup_sort);
    if (is_cursor_dup_sort) {
        dup_cursors_[table] = cursor;
    } else {
        cursors_[table] = cursor;
    }
    co_return cursor;
}

std::shared_ptr<chain::ChainStorage> LocalTransaction::make_storage() {
    // The calling thread *must* be the *same* which created this LocalTransaction instance
    return std::make_shared<chain::LocalChainStorage>(
        DataModel{tx_, data_store_.blocks_repository}, chain_config_);
}

Task<TxnId> LocalTransaction::first_txn_num_in_block(BlockNum block_num) {
    auto canonical_body_for_storage = [this](BlockNum bn) -> Task<std::optional<Bytes>> {
        DataModel access_layer{tx_, data_store_.blocks_repository};
        co_return access_layer.read_raw_body_for_storage_from_snapshot(bn);
    };
    const auto min_txn_num = co_await txn::min_tx_num(*this, block_num, canonical_body_for_storage);
    co_return min_txn_num + /*txn_index=*/0;
}

Task<GetLatestResult> LocalTransaction::get_latest(GetLatestRequest request) {
    ensure(request.sub_key.empty(), "LocalTransaction::get_latest sub_key support not implemented");

    if (!kTable2EntityNames.contains(request.table)) {
        co_return GetAsOfResult{};
    }

    const EntityName domain_name = kTable2EntityNames.at(request.table);
    RawDomainGetLatestQuery query{
        domain_name,
        data_store_.chaindata.domain(domain_name),
        tx_,
        data_store_.state_repository_latest,
        data_store_.query_caches,
    };
    auto result = query.exec(request.key);
    if (!result) {
        co_return GetLatestResult{};
    }
    co_return GetLatestResult{.success = true, .value = std::move(result->value)};
}

Task<GetAsOfResult> LocalTransaction::get_as_of(GetAsOfRequest request) {
    ensure(request.sub_key.empty(), "LocalTransaction::get_as_of sub_key support not implemented");

    if (!kTable2EntityNames.contains(request.table)) {
        co_return GetAsOfResult{};
    }

    const EntityName domain_name = kTable2EntityNames.at(request.table);
    std::optional<Bytes> value;
    if (domain_name == state::kDomainNameAccounts) {
        value = query_domain_as_of<AccountsDomainGetAsOfQuery>(domain_name, request.key, request.timestamp);
    } else if (domain_name == state::kDomainNameStorage) {
        value = query_domain_as_of<StorageDomainGetAsOfQuery>(domain_name, request.key, request.timestamp);
    } else if (domain_name == state::kDomainNameCode) {
        value = query_domain_as_of<CodeDomainGetAsOfQuery>(domain_name, request.key, request.timestamp);
    } else if (domain_name == state::kDomainNameCommitment) {
        value = query_domain_as_of<CommitmentDomainGetAsOfQuery>(domain_name, request.key, request.timestamp);
    } else if (domain_name == state::kDomainNameReceipts) {
        value = query_domain_as_of<ReceiptsDomainGetAsOfQuery>(domain_name, request.key, request.timestamp);
    }
    if (!value) {
        co_return GetAsOfResult{};
    }
    co_return GetAsOfResult{.success = true, .value = std::move(*value)};
}

Task<HistoryPointResult> LocalTransaction::history_seek(HistoryPointRequest request) {
    if (!kTable2EntityNames.contains(request.table)) {
        co_return HistoryPointResult{};
    }

    const EntityName domain_name = kTable2EntityNames.at(request.table);
    const kvdb::Domain domain = data_store_.chaindata.domain(domain_name);
    if (!domain.history) {
        co_return HistoryPointResult{};
    }

    const auto timestamp = static_cast<datastore::Timestamp>(request.timestamp);

    std::optional<Bytes> value;
    if (domain_name == state::kDomainNameAccounts) {
        value = query_history_get<AccountsHistoryGetQuery>(*domain.history, request.key, timestamp);
    } else if (domain_name == state::kDomainNameStorage) {
        value = query_history_get<StorageHistoryGetQuery>(*domain.history, request.key, timestamp);
    } else if (domain_name == state::kDomainNameCode) {
        value = query_history_get<CodeHistoryGetQuery>(*domain.history, request.key, timestamp);
    } else if (domain_name == state::kDomainNameCommitment) {
        value = query_history_get<CommitmentHistoryGetQuery>(*domain.history, request.key, timestamp);
    } else if (domain_name == state::kDomainNameReceipts) {
        value = query_history_get<ReceiptsHistoryGetQuery>(*domain.history, request.key, timestamp);
    }
    if (!value) {
        co_return HistoryPointResult{};
    }
    co_return HistoryPointResult{.success = true, .value = std::move(*value)};
}

template <Value V, std::ranges::input_range Range>
    requires std::convertible_to<std::iter_value_t<std::ranges::iterator_t<Range>>, V>
struct RangeStreamIterator : StreamIterator<V> {
    using RangeIterator = std::ranges::iterator_t<Range>;
    using iterator = RangeIterator;
    using value_type = V;

    explicit RangeStreamIterator(Range&& range) : range_(std::move(range)), it_(std::ranges::begin(range_)) {}

    Task<bool> has_next() override {
        co_return it_ != std::ranges::end(range_);
    }

    Task<std::optional<value_type>> next() override {
        if (it_ == std::ranges::end(range_)) {
            co_return std::nullopt;
        }
        const auto value = *it_;
        ++it_;
        co_return value;
    }

  private:
    Range range_;
    RangeIterator it_;
};

struct TimestampConverter {
    Timestamp operator()(datastore::Timestamp ts) const {
        return static_cast<Timestamp>(ts);
    }
};
using TimestampView = std::ranges::take_view<
    std::ranges::transform_view<RawInvertedIndexRangeByKeyQueryResult, TimestampConverter>>;
using TimestampViewIterator = decltype(std::declval<TimestampView>().begin());
static_assert(std::is_same_v<TimestampViewIterator::value_type, Timestamp>);
using TimestampStreamIterator = RangeStreamIterator<Timestamp, TimestampView>;

Task<TimestampStreamReply> LocalTransaction::index_range(IndexRangeRequest request) {
    if (!kTable2EntityNames.contains(request.table)) {
        co_return TimestampStreamReply{EmptyStreamFactory<Timestamp>};
    }

    auto timestamp_stream_factory = [this, request = std::move(request)]() mutable -> Task<TimestampStream> {
        const EntityName inverted_index_name = kTable2EntityNames.at(request.table);
        RawInvertedIndexRangeByKeyQuery query{
            inverted_index_name,
            data_store_.chaindata,
            tx_,
            data_store_.state_repository_historical,
        };
        datastore::TimestampRange ts_range = as_datastore_ts_range({request.from_timestamp, request.to_timestamp}, !request.ascending_order);
        const size_t limit = (request.limit == kUnlimited) ? std::numeric_limits<size_t>::max() : static_cast<size_t>(request.limit);

        auto timestamps = query.exec(request.key, std::move(ts_range), request.ascending_order) |
                          std::views::transform(TimestampConverter{}) |
                          std::views::take(limit);
        static_assert(std::is_same_v<TimestampView, decltype(timestamps)>);

        co_return TimestampStream{std::make_unique<TimestampStreamIterator>(std::move(timestamps))};
    };
    co_return TimestampStreamReply{std::move(timestamp_stream_factory)};
}

using RawHistoryRangeView = std::ranges::take_view<RawHistoryRangeInPeriodQueryResult>;
using RawHistoryRangeViewIterator = decltype(std::declval<RawHistoryRangeView>().begin());
static_assert(std::is_same_v<RawHistoryRangeViewIterator::value_type, RawKeyValue>);
using RawHistoryRangeStreamIterator = RangeStreamIterator<RawKeyValue, RawHistoryRangeView>;

Task<KeyValueStreamReply> LocalTransaction::history_range(HistoryRangeRequest request) {
    if (!kTable2EntityNames.contains(request.table)) {
        co_return KeyValueStreamReply{EmptyStreamFactory<RawKeyValue>};
    }

    auto key_value_stream_factory = [this, request = std::move(request)]() mutable -> Task<KeyValueStream> {
        const EntityName entity_name = kTable2EntityNames.at(request.table);
        RawHistoryRangeInPeriodQuery query{
            entity_name,
            data_store_.chaindata,
            tx_,
            data_store_.state_repository_historical,
        };

        datastore::TimestampRange ts_range = as_datastore_ts_range({request.from_timestamp, request.to_timestamp}, !request.ascending_order);
        const size_t limit = (request.limit == kUnlimited) ? std::numeric_limits<size_t>::max() : static_cast<size_t>(request.limit);

        auto history_kv = query.exec(ts_range, request.ascending_order) | std::views::take(limit);
        static_assert(std::is_same_v<RawHistoryRangeView, decltype(history_kv)>);

        co_return KeyValueStream{std::make_unique<RawHistoryRangeStreamIterator>(std::move(history_kv))};
    };
    co_return KeyValueStreamReply{std::move(key_value_stream_factory)};
}

using RawDomainRangeView = std::ranges::take_view<RawDomainRangeAsOfQueryResult>;
using RawDomainRangeViewViewIterator = decltype(std::declval<RawDomainRangeView>().begin());
static_assert(std::is_same_v<RawDomainRangeViewViewIterator::value_type, RawKeyValue>);
using RawDomainRangeStreamIterator = RangeStreamIterator<RawKeyValue, RawDomainRangeView>;

Task<KeyValueStreamReply> LocalTransaction::range_as_of(DomainRangeRequest request) {
    if (!kTable2EntityNames.contains(request.table)) {
        co_return KeyValueStreamReply{EmptyStreamFactory<RawKeyValue>};
    }

    auto key_value_stream_factory = [this, request = std::move(request)]() mutable -> Task<KeyValueStream> {
        const EntityName entity_name = kTable2EntityNames.at(request.table);
        RawDomainRangeAsOfQuery query{
            entity_name,
            data_store_.chaindata,
            tx_,
            data_store_.state_repository_latest,
            data_store_.state_repository_historical,
        };

        std::optional<datastore::Timestamp> timestamp;
        if (request.timestamp && (*request.timestamp >= 0)) {
            timestamp = static_cast<datastore::Timestamp>(*request.timestamp);
        }
        const size_t limit = (request.limit == kUnlimited) ? std::numeric_limits<size_t>::max() : static_cast<size_t>(request.limit);

        auto domain_kv = query.exec(request.from_key, request.to_key, timestamp, request.ascending_order, request.skip_empty_values) |
                         std::views::take(limit);
        static_assert(std::is_same_v<RawDomainRangeView, decltype(domain_kv)>);

        co_return KeyValueStream{std::make_unique<RawDomainRangeStreamIterator>(std::move(domain_kv))};
    };
    co_return KeyValueStreamReply{std::move(key_value_stream_factory)};
}

}  // namespace silkworm::db::kv::api
