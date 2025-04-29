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

#include "sequence.hpp"
#include "temporal_range.hpp"

namespace silkworm::db::kv::api {

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

    class Iterator : public StreamIterator<V> {
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

    Task<Stream<V>> operator()() {
        auto current = co_await next_page_provider_("");
        co_return std::make_unique<Iterator>(next_page_provider_, std::move(current));
    }

  private:
    Paginator next_page_provider_;
};

template <typename V>
Task<std::vector<V>> paginated_to_vector(PaginatedSequence<V>& paginated) {
    auto it = co_await paginated();
    co_return co_await stream_to_vector(it);
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

    class Iterator : public StreamIterator<KVPair> {
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

    Task<Stream<KVPair>> operator()() {
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
    auto it = co_await paginated();
    while (const auto value = co_await it->next()) {
        all_values.emplace_back(*value);
    }
    co_return all_values;
}

using PaginatedTimestamps = PaginatedSequence<Timestamp>;
using PaginatedKeysValues = PaginatedSequencePair<Bytes, Bytes>;

}  // namespace silkworm::db::kv::api
