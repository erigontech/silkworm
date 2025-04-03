// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <concepts>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <tuple>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/infra/common/ensure.hpp>

#include "key_value.hpp"

namespace silkworm::db::kv::api {

template <typename V>
concept Value = std::copyable<V>;

//! Definition of asynchronous paginated iterator (a.k.a. stream)
template <Value V>
struct PaginatedIterator {
    virtual ~PaginatedIterator() = default;

    virtual Task<bool> has_next() = 0;
    virtual Task<std::optional<V>> next() = 0;
};

template <Value V>
using PaginatedStream = std::unique_ptr<PaginatedIterator<V>>;

//! Empty paginated iterator
template <Value V>
class EmptyIterator : public PaginatedIterator<V> {
  public:
    using value_type = V;

    Task<bool> has_next() override { co_return false; }

    Task<std::optional<value_type>> next() override { co_return std::nullopt; }
};

//! Sequence of values produced by pagination using some asynchronous page provider function.
template <Value V>
class PaginatedSequence {
  public:
    using Page = std::vector<V>;
    struct PageResult {
        Page values;
        std::string next_page_token;
    };
    using PageToken = std::string;
    using Paginator = std::function<Task<PageResult>(PageToken)>;

    class Iterator : public PaginatedIterator<V> {
      public:
        using value_type = V;

        Task<bool> has_next() override { co_return it_ != current_.values.cend(); }

        Task<std::optional<V>> next() override {
            if (it_ == current_.values.cend()) {
                if (!current_.next_page_token.empty()) {
                    current_ = co_await next_page_provider_(std::move(current_.next_page_token));
                    it_ = current_.values.cbegin();
                }
            }
            if (it_ == current_.values.cend()) {
                co_return std::nullopt;
            }
            const auto value = *it_;
            ++it_;
            co_return value;
        }

        Iterator(Paginator& next_page_provider, PageResult current) noexcept
            : next_page_provider_(next_page_provider),
              current_(std::move(current)),
              it_(current_.values.cbegin()) {}
        Iterator(const Iterator& other) noexcept
            : next_page_provider_(other.next_page_provider_),
              current_(other.current_),
              it_(current_.values.cbegin() + std::distance(other.current_.values.cbegin(), other.it_)) {}
        Iterator(Iterator&& other) noexcept
            : next_page_provider_(other.next_page_provider_) {
            const auto distance = std::distance(other.current_.values.cbegin(), other.it_);
            current_ = std::move(other.current_);  // NOLINT(*-prefer-member-initializer)
            it_ = current_.values.cbegin() + distance;
        }

      private:
        Paginator& next_page_provider_;
        PageResult current_;
        typename Page::const_iterator it_;
    };

    explicit PaginatedSequence(Paginator next_page_provider) noexcept
        : next_page_provider_(std::move(next_page_provider)) {}

    Task<PaginatedStream<V>> begin() {
        auto current = co_await next_page_provider_("");
        co_return std::make_unique<Iterator>(next_page_provider_, std::move(current));
    }

  private:
    Paginator next_page_provider_;
};

template <Value V, Value R = V>
Task<std::vector<R>> paginated_iterator_to_vector(const PaginatedStream<V>& it) {
    std::vector<R> all_values;
    if (!it) {
        co_return all_values;
    }
    while (const auto value = co_await it->next()) {
        all_values.emplace_back(*value);
    }
    co_return all_values;
}

template <typename V>
Task<std::vector<V>> paginated_to_vector(PaginatedSequence<V>& paginated) {
    auto it = co_await paginated.begin();
    co_return co_await paginated_iterator_to_vector(it);
}

//! Sequence of keys and values produced by pagination using some asynchronous page provider function.
template <Value K, Value V>
class PaginatedSequencePair {
  public:
    using KPage = std::vector<K>;
    using VPage = std::vector<V>;
    struct PageResult {
        KPage keys;
        VPage values;
        std::string next_page_token;
    };
    using PageToken = std::string;
    using Paginator = std::function<Task<PageResult>(PageToken)>;
    using KVPair = std::pair<K, V>;

    class Iterator : public PaginatedIterator<KVPair> {
      public:
        using value_type = KVPair;

        Task<bool> has_next() override {
            const bool has_next_key = key_it_ != current_.keys.cend();
            const bool has_next_value = value_it_ != current_.values.cend();
            SILKWORM_ASSERT(has_next_key == has_next_value);
            co_return has_next_key;
        }

        Task<std::optional<value_type>> next() override {
            if (key_it_ == current_.keys.cend()) {
                SILKWORM_ASSERT(value_it_ == current_.values.cend());
                if (!current_.next_page_token.empty()) {
                    current_ = co_await next_page_provider_(std::move(current_.next_page_token));
                    key_it_ = current_.keys.cbegin();
                    value_it_ = current_.values.cbegin();
                }
            }
            if (key_it_ == current_.keys.cend()) {
                SILKWORM_ASSERT(value_it_ == current_.values.cend());
                co_return std::nullopt;
            }
            const std::pair<K, V> key_value{std::move(*key_it_), std::move(*value_it_)};
            ++key_it_, ++value_it_;
            co_return key_value;
        }

        Iterator(Paginator& next_page_provider, PageResult current) noexcept
            : next_page_provider_(next_page_provider),
              current_(std::move(current)),
              key_it_(current_.keys.cbegin()),
              value_it_(current_.values.cbegin()) {}
        Iterator(const Iterator& other) noexcept
            : next_page_provider_(other.next_page_provider_),
              current_(other.current_),
              key_it_(current_.keys.cbegin() + std::distance(other.current_.keys.cbegin(), other.key_it_)),
              value_it_(current_.values.cbegin() + std::distance(other.current_.values.cbegin(), other.value_it_)) {}
        Iterator(Iterator&& other) noexcept
            : next_page_provider_(other.next_page_provider_) {
            const auto key_distance = std::distance(other.current_.keys.cbegin(), other.key_it_);
            const auto value_distance = std::distance(other.current_.values.cbegin(), other.value_it_);
            SILKWORM_ASSERT(key_distance == value_distance);
            current_ = std::move(other.current_);  // NOLINT(*-prefer-member-initializer)
            key_it_ = current_.keys.cbegin() + key_distance;
            value_it_ = current_.values.cbegin() + value_distance;
        }

      private:
        Paginator& next_page_provider_;
        PageResult current_;
        typename KPage::const_iterator key_it_;
        typename VPage::const_iterator value_it_;
    };

    explicit PaginatedSequencePair(Paginator next_page_provider) noexcept
        : next_page_provider_(std::move(next_page_provider)) {}

    Task<PaginatedStream<KVPair>> begin() {
        auto current = co_await next_page_provider_("");
        ensure(current.keys.size() == current.values.size(), "PaginatedSequencePair::begin keys/values size mismatch");
        co_return std::make_unique<Iterator>(next_page_provider_, std::move(current));
    }

  private:
    Paginator next_page_provider_;
};

template <Value K, Value V>
Task<std::vector<KeyValue>> paginated_to_vector(PaginatedSequencePair<K, V>& paginated) {
    std::vector<KeyValue> all_values;
    auto it = co_await paginated.begin();
    while (const auto value = co_await it->next()) {
        all_values.emplace_back(*value);
    }
    co_return all_values;
}

//! Paginated iterator implementing 'intersection' set operation between 2 paginated iterators
template <Value V>
class IntersectionIterator : public PaginatedIterator<V> {
  public:
    using value_type = V;

    IntersectionIterator(PaginatedStream<V> it1, PaginatedStream<V> it2, size_t limit)
        : it1_(std::move(it1)), it2_(std::move(it2)), limit_(limit) {}

    Task<bool> has_next() override {
        if (!initialized_) {
            initialized_ = true;
            co_await advance();
        }
        co_return limit_ != 0 && next_v1_&& next_v2_;
    }

    Task<std::optional<value_type>> next() override {
        if (limit_ == 0) {
            co_return std::nullopt;
        }
        --limit_;
        if (!initialized_) {
            initialized_ = true;
            co_await advance();
        }
        const auto next_v1 = next_v1_;
        co_await advance();
        co_return next_v1;
    }

  private:
    Task<std::optional<value_type>> advance() {
        next_v1_ = co_await it1_->next();
        next_v2_ = co_await it2_->next();
        while (next_v1_ && next_v2_) {
            if (*next_v1_ < *next_v2_) {
                next_v1_ = co_await it1_->next();
                continue;
            }
            if (*next_v1_ == *next_v2_) {
                co_return next_v1_;  // *next_v2_ and *next_v2_ are equivalent
            } else {
                next_v2_ = co_await it2_->next();
                continue;
            }
        }
        next_v1_.reset();
        next_v2_.reset();
        co_return std::nullopt;
    }

    bool initialized_{false};
    PaginatedStream<V> it1_;
    PaginatedStream<V> it2_;
    std::optional<value_type> next_v1_;
    std::optional<value_type> next_v2_;
    size_t limit_;
};

template <Value V>
PaginatedStream<V> set_intersection(PaginatedStream<V> it1, PaginatedStream<V> it2, size_t limit = std::numeric_limits<size_t>::max()) {
    if (!it1 || !it2) {
        return std::make_unique<EmptyIterator<V>>();
    }
    return std::make_unique<IntersectionIterator<V>>(std::move(it1), std::move(it2), limit);
}

//! Paginated iterator implementing 'union' set operation between 2 paginated iterators
template <Value V>
class UnionIterator : public PaginatedIterator<V> {
  public:
    using value_type = V;

    UnionIterator(PaginatedStream<V> it1, PaginatedStream<V> it2, bool ascending, size_t limit)
        : it1_(std::move(it1)), it2_(std::move(it2)), ascending_(ascending), limit_(limit) {}

    Task<bool> has_next() override {
        co_return limit_ != 0 && (co_await it1_->has_next() || co_await it2_->has_next() || next_v1_ || next_v2_);
    }

    Task<std::optional<value_type>> next() override {
        if (limit_ == 0) {
            co_return std::nullopt;
        }
        --limit_;
        if (!next_v1_ && co_await it1_->has_next()) {
            next_v1_ = co_await it1_->next();
        }
        if (!next_v2_ && co_await it2_->has_next()) {
            next_v2_ = co_await it2_->next();
        }
        if (!next_v1_ && !next_v2_) {
            co_return std::nullopt;
        }
        if (next_v1_ && next_v2_) {
            if ((ascending_ && *next_v1_ < *next_v2_) || (!ascending_ && *next_v1_ > *next_v2_)) {
                const auto v1 = *next_v1_;
                next_v1_ = co_await it1_->next();
                co_return v1;
            } else if (*next_v1_ == *next_v2_) {
                const auto v1 = *next_v1_;
                next_v1_ = co_await it1_->next();
                next_v2_ = co_await it2_->next();
                co_return v1;  // *v1 and *v2 are equivalent
            }
            const auto v2 = *next_v2_;
            next_v2_ = co_await it2_->next();
            co_return v2;
        }
        if (next_v1_) {
            const auto v1 = *next_v1_;
            next_v1_ = co_await it1_->next();
            co_return v1;
        }
        const auto v2 = *next_v2_;
        next_v2_ = co_await it2_->next();
        co_return v2;
    }

  private:
    PaginatedStream<V> it1_;
    PaginatedStream<V> it2_;
    std::optional<value_type> next_v1_;
    std::optional<value_type> next_v2_;
    bool ascending_;
    size_t limit_;
};

template <Value V>
PaginatedStream<V> set_union(PaginatedStream<V> it1, PaginatedStream<V> it2, bool ascending = true, size_t limit = std::numeric_limits<size_t>::max()) {
    if (!it1 && !it2) {
        return std::make_unique<EmptyIterator<V>>();
    }
    if (!it1) {
        return it2;
    }
    if (!it2) {
        return it1;
    }
    return std::make_unique<UnionIterator<V>>(std::move(it1), std::move(it2), ascending, limit);
}

template <Value V>
class RangePaginatedIterator : public PaginatedIterator<V> {
  public:
    using value_type = V;

    RangePaginatedIterator(V from, V to)
        : current_(from), to_(to) {}

    Task<bool> has_next() override {
        co_return current_ < to_;
    }

    Task<std::optional<value_type>> next() override {
        if (current_ >= to_) {
            co_return std::nullopt;
        }
        co_return current_++;
    }

  private:
    V current_;
    V to_;
};

template <Value V>
PaginatedStream<V> make_range_stream(V from, V to) {
    return std::make_unique<RangePaginatedIterator<V>>(from, to);
}
}  // namespace silkworm::db::kv::api
