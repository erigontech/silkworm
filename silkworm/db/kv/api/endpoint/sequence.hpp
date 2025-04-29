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

//! Definition of asynchronous iterator (a.k.a. stream)
template <Value V>
struct StreamIterator {
    virtual ~StreamIterator() = default;

    virtual Task<bool> has_next() = 0;
    virtual Task<std::optional<V>> next() = 0;
};

template <Value V>
using Stream = std::unique_ptr<StreamIterator<V>>;

//! Empty iterator
template <Value V>
class EmptyIterator : public StreamIterator<V> {
  public:
    using value_type = V;

    Task<bool> has_next() override { co_return false; }

    Task<std::optional<value_type>> next() override { co_return std::nullopt; }
};

template <Value V>
using EmptyStream = std::unique_ptr<EmptyIterator<V>>;

template <Value V>
using StreamFactory = std::function<Task<Stream<V>>()>;

template <Value V>
auto EmptyStreamFactory = []() -> Task<Stream<V>> { co_return std::make_unique<EmptyIterator<V>>(); };

template <Value V>
class StreamReply {
  public:
    explicit StreamReply(StreamFactory<V> factory) : factory_(std::move(factory)) {}

    Task<Stream<V>> begin() const { co_return co_await factory_(); }

  private:
    StreamFactory<V> factory_;
};

template <Value V, Value R = V>
Task<std::vector<R>> stream_to_vector(const Stream<V>& it) {
    std::vector<R> all_values;
    if (!it) {
        co_return all_values;
    }
    while (const auto value = co_await it->next()) {
        all_values.emplace_back(*value);
    }
    co_return all_values;
}

template <Value V, Value R = V>
Task<std::vector<R>> stream_to_vector(const StreamReply<V>& reply) {
    auto it = co_await reply.begin();
    co_return co_await stream_to_vector<V, R>(it);
}

//! Stream iterator implementing 'intersection' set operation between 2 stream iterators
template <Value V>
class IntersectionIterator : public StreamIterator<V> {
  public:
    using value_type = V;

    IntersectionIterator(Stream<V> it1, Stream<V> it2, size_t limit)
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
    Stream<V> it1_;
    Stream<V> it2_;
    std::optional<value_type> next_v1_;
    std::optional<value_type> next_v2_;
    size_t limit_;
};

template <Value V>
Stream<V> set_intersection(Stream<V> it1, Stream<V> it2, size_t limit = std::numeric_limits<size_t>::max()) {
    if (!it1 || !it2) {
        return std::make_unique<EmptyIterator<V>>();
    }
    return std::make_unique<IntersectionIterator<V>>(std::move(it1), std::move(it2), limit);
}

//! Stream iterator implementing 'union' set operation between 2 stream iterators
template <Value V>
class UnionIterator : public StreamIterator<V> {
  public:
    using value_type = V;

    UnionIterator(Stream<V> it1, Stream<V> it2, bool ascending, size_t limit)
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
    Stream<V> it1_;
    Stream<V> it2_;
    std::optional<value_type> next_v1_;
    std::optional<value_type> next_v2_;
    bool ascending_;
    size_t limit_;
};

template <Value V>
Stream<V> set_union(Stream<V> it1, Stream<V> it2, bool ascending = true, size_t limit = std::numeric_limits<size_t>::max()) {
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
class RangeIterator : public StreamIterator<V> {
  public:
    using value_type = V;

    RangeIterator(V from, V to)
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
Stream<V> make_range_stream(V from, V to) {
    return std::make_unique<RangeIterator<V>>(from, to);
}

}  // namespace silkworm::db::kv::api
