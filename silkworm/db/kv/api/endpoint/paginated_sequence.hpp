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
#include <iostream>
#include <optional>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

namespace silkworm::db::kv::api {

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
        Iterator(Paginator& next_page_provider) noexcept
            : next_page_provider_(next_page_provider) {}

      private:
        Paginator& next_page_provider_;
        PageResult current_;
        Page::const_iterator it_;  // empty i.e. sentinel value
    };

    explicit PaginatedSequence(Paginator next_page_provider) noexcept
        : next_page_provider_(next_page_provider) {}

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

}  // namespace silkworm::db::kv::api
