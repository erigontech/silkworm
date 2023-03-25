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

#pragma once

#include <vector>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>

#include <silkworm/sentry/common/enode_url.hpp>

namespace silkworm::sentry::discovery {

class Discovery {
  public:
    Discovery(std::vector<common::EnodeUrl> peer_urls);

    boost::asio::awaitable<void> start();

    boost::asio::awaitable<std::vector<common::EnodeUrl>> request_peer_urls(
        size_t max_count,
        std::vector<common::EnodeUrl> exclude_urls);

    bool is_static_peer_url(const common::EnodeUrl& peer_url);

  private:
    const std::vector<common::EnodeUrl> peer_urls_;
};

}  // namespace silkworm::sentry::discovery
