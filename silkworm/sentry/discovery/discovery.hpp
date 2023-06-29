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

#include <filesystem>
#include <functional>
#include <memory>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/enode_url.hpp>

namespace silkworm::sentry::discovery {

class DiscoveryImpl;

class Discovery {
  public:
    explicit Discovery(
        std::vector<common::EnodeUrl> peer_urls,
        bool with_dynamic_discovery,
        const std::filesystem::path& data_dir_path,
        std::function<common::EccKeyPair()> node_key,
        uint16_t disc_v4_port);
    ~Discovery();

    Discovery(const Discovery&) = delete;
    Discovery& operator=(const Discovery&) = delete;

    Task<void> run();

    Task<std::vector<common::EnodeUrl>> request_peer_urls(
        size_t max_count,
        std::vector<common::EnodeUrl> exclude_urls);

    bool is_static_peer_url(const common::EnodeUrl& peer_url);

  private:
    std::unique_ptr<DiscoveryImpl> p_impl_;
};

}  // namespace silkworm::sentry::discovery
