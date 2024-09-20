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

#include <functional>
#include <optional>
#include <tuple>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/infra/common/ensure.hpp>

#include "key_value.hpp"

namespace silkworm::db::kv::api {

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
        T operator*() {
            return std::move(*it_);
        }

        Task<void> operator++() {
            ++it_;
            if (it_ == current_.values.cend()) {
                if (current_.has_more) {
                    current_ = co_await next_page_provider_();
                    it_ = current_.values.cbegin();
                } else {
                    it_ = typename Page::const_iterator();  // empty i.e. sentinel value
                }
            }
        }

        bool operator==(const Iterator& other) const noexcept {
            return it_ == other.it_;
        }

        bool operator!=(const Iterator& other) const noexcept {
            return !(*this == other);
        }

        Iterator(Paginator& next_page_provider, PageResult current) noexcept
            : next_page_provider_(next_page_provider), current_(std::move(current)), it_{current_.values.cbegin()} {}
        explicit Iterator(Paginator& next_page_provider) noexcept
            : next_page_provider_(next_page_provider) {}

      private:
        Paginator& next_page_provider_;
        PageResult current_;
        typename Page::const_iterator it_;  // empty i.e. sentinel value
    };

    explicit PaginatedSequence(Paginator next_page_provider) noexcept
        : next_page_provider_(std::move(next_page_provider)) {}

    Task<Iterator> begin() {
        auto current = co_await next_page_provider_();
        co_return Iterator{next_page_provider_, std::move(current)};
    }

    Iterator end() noexcept {
        return Iterator{next_page_provider_};
    }

  private:
    Paginator next_page_provider_;
};

template <typename T>
Task<std::vector<T>> paginated_to_vector(PaginatedSequence<T>& paginated) {
    std::vector<T> all_values;
    auto it = co_await paginated.begin();
    while (it != paginated.end()) {
        all_values.emplace_back(*it);
        co_await ++it;
    }
    co_return all_values;
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
        std::pair<K, V> operator*() {
            return {std::move(*key_it_), std::move(*value_it_)};
        }

        Task<void> operator++() {
            ++key_it_;
            ++value_it_;
            if (key_it_ == current_.keys.cend()) {
                SILKWORM_ASSERT(value_it_ == current_.values.cend());
                if (current_.has_more) {
                    current_ = co_await next_page_provider_();
                    key_it_ = current_.keys.cbegin();
                    value_it_ = current_.values.cbegin();
                } else {
                    key_it_ = typename KPage::const_iterator();    // empty i.e. sentinel value
                    value_it_ = typename VPage::const_iterator();  // empty i.e. sentinel value
                }
            }
        }

        bool operator==(const Iterator& other) const noexcept {
            return key_it_ == other.key_it_ && value_it_ == other.value_it_;
        }

        bool operator!=(const Iterator& other) const noexcept {
            return !(*this == other);
        }

        Iterator(Paginator& next_page_provider, PageResult current) noexcept
            : next_page_provider_(next_page_provider),
              current_(std::move(current)),
              key_it_{current_.keys.cbegin()},
              value_it_{current_.values.cbegin()} {}
        explicit Iterator(Paginator& next_page_provider) noexcept
            : next_page_provider_(next_page_provider) {}

      private:
        Paginator& next_page_provider_;
        PageResult current_;
        typename KPage::const_iterator key_it_;    // empty i.e. sentinel value
        typename VPage::const_iterator value_it_;  // empty i.e. sentinel value
    };

    explicit PaginatedSequencePair(Paginator next_page_provider) noexcept
        : next_page_provider_(std::move(next_page_provider)) {}

    Task<Iterator> begin() {
        auto current = co_await next_page_provider_();
        ensure(current.keys.size() == current.values.size(), "PaginatedSequencePair::begin keys/values size mismatch");
        co_return Iterator{next_page_provider_, std::move(current)};
    }

    Iterator end() noexcept {
        return Iterator{next_page_provider_};
    }

  private:
    Paginator next_page_provider_;
};

template <typename K, typename V>
Task<std::vector<KeyValue>> paginated_to_vector(PaginatedSequencePair<K, V>& paginated) {
    std::vector<KeyValue> all_keys_and_values;
    auto it = co_await paginated.begin();
    while (it != paginated.end()) {
        all_keys_and_values.emplace_back(*it);
        co_await ++it;
    }
    co_return all_keys_and_values;
}

}  // namespace silkworm::db::kv::api
