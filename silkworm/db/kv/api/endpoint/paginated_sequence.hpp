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

#include <concepts>
#include <functional>
#include <iterator>
#include <optional>
#include <tuple>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/infra/common/ensure.hpp>

#include "key_value.hpp"

namespace silkworm::db::kv::api {

//! Definition of asynchronous paginated iterator (a.k.a. stream)
template <class I>
concept PaginatedIterator =
    requires(I i) {
        typename I::value_type;
        { i.has_next() } -> std::same_as<bool>;
        { i.next() } -> std::same_as<Task<std::optional<typename std::iter_value_t<I>>>>;
    };

//! Sequence of values produced by pagination using some asynchronous page provider function.
template <typename T>
class PaginatedSequence {
  public:
    using Page = std::vector<T>;
    struct PageResult {
        Page values;
        bool has_more{false};
    };
    using Paginator = std::function<Task<PageResult>()>;

    class Iterator {
      public:
        using value_type = T;

        bool has_next() const { return it_ != current_.values.cend(); }

        Task<std::optional<T>> next() {
            if (it_ == current_.values.cend()) {
                if (current_.has_more) {
                    current_ = co_await next_page_provider_();
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
            : next_page_provider_(next_page_provider), current_(std::move(current)), it_{current_.values.cbegin()} {}

      private:
        Paginator& next_page_provider_;
        PageResult current_;
        typename Page::const_iterator it_;
    };

    static_assert(PaginatedIterator<Iterator>);

    explicit PaginatedSequence(Paginator next_page_provider) noexcept
        : next_page_provider_(std::move(next_page_provider)) {}

    Task<Iterator> begin() {
        auto current = co_await next_page_provider_();
        co_return Iterator{next_page_provider_, std::move(current)};
    }

  private:
    Paginator next_page_provider_;
};

template <PaginatedIterator I>
Task<std::vector<typename I::value_type>> paginated_iterator_to_vector(I it) {
    std::vector<typename I::value_type> all_values;
    while (const auto value = co_await it.next()) {
        all_values.emplace_back(*value);
    }
    co_return all_values;
}

template <typename T>
Task<std::vector<T>> paginated_to_vector(PaginatedSequence<T>& paginated) {
    co_return co_await paginated_iterator_to_vector(co_await paginated.begin());
}

//! Sequence of keys and values produced by pagination using some asynchronous page provider function.
template <typename K, typename V>
class PaginatedSequencePair {
  public:
    using KPage = std::vector<K>;
    using VPage = std::vector<V>;
    struct PageResult {
        KPage keys;
        VPage values;
        bool has_more{false};
    };
    using Paginator = std::function<Task<PageResult>()>;

    class Iterator {
      public:
        using value_type = std::pair<K, V>;

        bool has_next() const {
            const bool has_next_key = key_it_ != current_.keys.cend();
            const bool has_next_value = value_it_ != current_.values.cend();
            SILKWORM_ASSERT(has_next_key == has_next_value);
            return has_next_key;
        }

        Task<std::optional<value_type>> next() {
            if (key_it_ == current_.keys.cend()) {
                SILKWORM_ASSERT(value_it_ == current_.values.cend());
                if (current_.has_more) {
                    current_ = co_await next_page_provider_();
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
              key_it_{current_.keys.cbegin()},
              value_it_{current_.values.cbegin()} {}

      private:
        Paginator& next_page_provider_;
        PageResult current_;
        typename KPage::const_iterator key_it_;
        typename VPage::const_iterator value_it_;
    };

    static_assert(PaginatedIterator<Iterator>);

    explicit PaginatedSequencePair(Paginator next_page_provider) noexcept
        : next_page_provider_(std::move(next_page_provider)) {}

    Task<Iterator> begin() {
        auto current = co_await next_page_provider_();
        ensure(current.keys.size() == current.values.size(), "PaginatedSequencePair::begin keys/values size mismatch");
        co_return Iterator{next_page_provider_, std::move(current)};
    }

  private:
    Paginator next_page_provider_;
};

template <typename K, typename V>
Task<std::vector<KeyValue>> paginated_to_vector(PaginatedSequencePair<K, V>& paginated) {
    std::vector<KeyValue> all_values;
    auto it = co_await paginated.begin();
    while (const auto value = co_await it.next()) {
        all_values.emplace_back(*value);
    }
    co_return all_values;
    // co_return co_await paginated_iterator_to_vector(co_await paginated.begin());
}

//! Paginated iterator implementing 'intersection' set operation between 2 paginated iterators
template <PaginatedIterator I>
class IntersectionIterator {
  public:
    using value_type = typename I::value_type;

    IntersectionIterator(I it1, I it2, size_t limit)
        : it1_(std::move(it1)), it2_(std::move(it2)), limit_(limit) {}

    bool has_next() const { return false; }  // TODO(canepat) implement

    Task<std::optional<value_type>> next() {
        if (limit_ == 0) {
            co_return std::nullopt;
        }
        --limit_;
        auto v1 = co_await it1_.next(), v2 = co_await it2_.next();
        if (!v1 || !v2) {
            co_return std::nullopt;
        }
        while (v1.has_value() && v2.has_value()) {
            if (*v1 < *v2) {
                v1 = co_await it1_.next();
                continue;
            }
            if (*v1 == *v2) {
                co_return v1;  // *v1 and *v2 are equivalent
            } else {
                v2 = co_await it2_.next();
                continue;
            }
        }
        co_return std::nullopt;
    }

  private:
    I it1_;
    I it2_;
    size_t limit_;
};

static_assert(PaginatedIterator<IntersectionIterator<PaginatedSequence<uint64_t>::Iterator>>);

template <PaginatedIterator I>
IntersectionIterator<I> set_intersection(I it1, I it2, size_t limit = std::numeric_limits<size_t>::max()) {
    return IntersectionIterator<I>{std::move(it1), std::move(it2), limit};
}

//! Paginated iterator implementing 'union' set operation between 2 paginated iterators
template <PaginatedIterator I>
class UnionIterator {
  public:
    using value_type = typename I::value_type;

    UnionIterator(I it1, I it2, bool ascending, size_t limit)
        : it1_(std::move(it1)), it2_(std::move(it2)), ascending_(ascending), limit_(limit) {}

    bool has_next() const { return limit_ != 0 && (it1_.has_next() || it2_.has_next() || next_v1_ || next_v2_); }

    Task<std::optional<value_type>> next() {
        if (limit_ == 0) {
            co_return std::nullopt;
        }
        --limit_;
        if (!next_v1_ && it1_.has_next()) {
            next_v1_ = co_await it1_.next();
        }
        if (!next_v2_ && it2_.has_next()) {
            next_v2_ = co_await it2_.next();
        }
        if (!next_v1_ && !next_v2_) {
            co_return std::nullopt;
        }
        if (next_v1_ && next_v2_) {
            if ((ascending_ && *next_v1_ < *next_v2_) || (!ascending_ && *next_v1_ > *next_v2_)) {
                const auto v1 = *next_v1_;
                next_v1_ = co_await it1_.next();
                co_return v1;
            } else if (*next_v1_ == *next_v2_) {
                const auto v1 = *next_v1_;
                next_v1_ = co_await it1_.next();
                next_v2_ = co_await it2_.next();
                co_return v1;  // *v1 and *v2 are equivalent
            }
            const auto v2 = *next_v2_;
            next_v2_ = co_await it2_.next();
            co_return v2;
        }
        if (next_v1_) {
            const auto v1 = *next_v1_;
            next_v1_ = co_await it1_.next();
            co_return v1;
        }
        const auto v2 = *next_v2_;
        next_v2_ = co_await it2_.next();
        co_return v2;
    }

  private:
    I it1_;
    I it2_;
    std::optional<value_type> next_v1_;
    std::optional<value_type> next_v2_;
    bool ascending_;
    size_t limit_;
};

static_assert(PaginatedIterator<UnionIterator<PaginatedSequence<uint64_t>::Iterator>>);

template <PaginatedIterator I>
UnionIterator<I> set_union(I it1, I it2, bool ascending = true, size_t limit = std::numeric_limits<size_t>::max()) {
    return UnionIterator<I>{std::move(it1), std::move(it2), ascending, limit};
}

}  // namespace silkworm::db::kv::api
