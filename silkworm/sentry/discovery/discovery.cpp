/*
   Copyright 2023 The Silkworm Authors

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

#include "discovery.hpp"

#include <algorithm>
#include <iterator>

#include <silkworm/sentry/common/random.hpp>

namespace silkworm::sentry::discovery {

using namespace boost::asio;

Discovery::Discovery(std::vector<common::EnodeUrl> peer_urls)
    : peer_urls_(std::move(peer_urls)) {
}

awaitable<void> Discovery::start() {
    co_return;
}

template <typename T>
static std::vector<T> exclude_vector_items(
    std::vector<T> items,
    std::vector<T> exclude_items) {
    std::vector<T> remaining_items;
    std::sort(items.begin(), items.end());
    std::sort(exclude_items.begin(), exclude_items.end());
    std::set_difference(
        items.begin(), items.end(),
        exclude_items.begin(), exclude_items.end(),
        std::inserter(remaining_items, remaining_items.begin()));
    return remaining_items;
}

awaitable<std::vector<common::EnodeUrl>> Discovery::request_peer_urls(
    size_t max_count,
    std::vector<common::EnodeUrl> exclude_urls) {
    auto peer_urls = exclude_vector_items(peer_urls_, std::move(exclude_urls));
    co_return common::random_vector_items(peer_urls, max_count);
}

}  // namespace silkworm::sentry::discovery
