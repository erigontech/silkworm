// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "pattern_aggregator.hpp"

#include <algorithm>
#include <functional>
#include <optional>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/db/datastore/etl/collector.hpp>

namespace silkworm::snapshots::seg {

using Pattern = PatternAggregator::Pattern;
using namespace std;
namespace etl {
    using namespace silkworm::datastore::etl;
}

static Bytes big_endian_encode(uint64_t value) {
    Bytes data(sizeof(uint64_t), 0);
    endian::store_big_u64(data.data(), value);
    return data;
}

static uint64_t big_endian_decode(ByteView encoded) {
    return endian::load_big_u64(encoded.data());
}

static bool operator>(const Pattern& p1, const Pattern& p2) {
    return (p1.score != p2.score)
               ? (p1.score > p2.score)
               : (p1.data > p2.data);
}

class PatternAggregatorImpl {
  public:
    explicit PatternAggregatorImpl(const filesystem::path& etl_work_path)
        : etl_work_path_(etl_work_path),
          collector_(make_unique<datastore::etl::Collector>(etl_work_path, datastore::etl::kOptimalBufferSize / 4)) {}

    void collect_pattern(Pattern pattern) {
        collector_->collect(std::move(pattern.data), big_endian_encode(pattern.score));
    }

    vector<Pattern> aggregate();

  private:
    /**
     * The max number of patterns to keep in reserve
     * while building the sorted list incrementally in order_by_score_and_limit.
     * Having more than kMaxPatterns patterns in consideration
     * produces 10% better compression ratio while still keeping RAM usage under control.
     * see DictReducerSoftLimit in erigon
     */
    static constexpr size_t kMaxPatternsSoftLimit = 1'000'000;

    // destination = SELECT data, sum(score) FROM source GROUP BY data
    static void sum_score_group_by_pattern(datastore::etl::Collector& source, datastore::etl::Collector& destination);

    // SELECT * FROM source ORDER BY score DESC LIMIT kMaxPatterns
    static vector<Pattern> order_by_score_and_limit(datastore::etl::Collector& source);

    filesystem::path etl_work_path_;
    unique_ptr<datastore::etl::Collector> collector_;
};

void PatternAggregatorImpl::sum_score_group_by_pattern(datastore::etl::Collector& source, datastore::etl::Collector& destination) {
    optional<Bytes> pending_pattern_data;
    uint64_t pending_pattern_score{};

    source.load([&](const datastore::etl::Entry& entry) {
        auto& pattern_data = entry.key;
        uint64_t pattern_score = big_endian_decode(entry.value);

        if (pattern_data == pending_pattern_data) {
            pending_pattern_score += pattern_score;
        } else {
            if (pending_pattern_data) {
                destination.collect(std::move(*pending_pattern_data), big_endian_encode(pending_pattern_score));
            }
            pending_pattern_data = pattern_data;
            pending_pattern_score = pattern_score;
        }
    });
    if (pending_pattern_data) {
        destination.collect(std::move(*pending_pattern_data), big_endian_encode(pending_pattern_score));
    }
}

vector<Pattern> PatternAggregatorImpl::order_by_score_and_limit(datastore::etl::Collector& source) {
    vector<Pattern> patterns;
    std::greater<> comparator;

    source.load([&](const datastore::etl::Entry& entry) {
        Pattern pattern{
            .data = Bytes{entry.key},
            .score = big_endian_decode(entry.value),
        };

        patterns.push_back(std::move(pattern));
        ranges::push_heap(patterns, comparator);

        if (patterns.size() > kMaxPatternsSoftLimit) {
            ranges::pop_heap(patterns, comparator);
            patterns.pop_back();
        }
    });

    ranges::sort(patterns, comparator);

    if (patterns.size() > PatternAggregator::kMaxPatterns) {
        patterns.resize(PatternAggregator::kMaxPatterns);
    }

    return patterns;
}

vector<Pattern> PatternAggregatorImpl::aggregate() {
    datastore::etl::Collector collector{etl_work_path_};
    sum_score_group_by_pattern(*collector_, collector);

    // the original collector_ is not needed anymore, free it
    collector_.reset();

    return order_by_score_and_limit(collector);
}

PatternAggregator::PatternAggregator(const filesystem::path& etl_work_path)
    : p_impl_(make_unique<PatternAggregatorImpl>(etl_work_path)) {}
PatternAggregator::~PatternAggregator() { static_assert(true); }

PatternAggregator::PatternAggregator(PatternAggregator&& other) noexcept
    : p_impl_(std::move(other.p_impl_)) {}
PatternAggregator& PatternAggregator::operator=(PatternAggregator&& other) noexcept {
    p_impl_ = std::move(other.p_impl_);
    return *this;
}

void PatternAggregator::collect_pattern(Pattern pattern) {
    p_impl_->collect_pattern(std::move(pattern));
}

vector<Pattern> PatternAggregator::aggregate(PatternAggregator aggregator) {
    return aggregator.p_impl_->aggregate();
}

}  // namespace silkworm::snapshots::seg
