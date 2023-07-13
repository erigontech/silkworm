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

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/enode_url.hpp>

namespace silkworm::sentry::discovery {

class DiscoveryImpl;

class Discovery {
  public:
    explicit Discovery(
        std::function<boost::asio::any_io_executor()> executor_pool,
        std::vector<EnodeUrl> peer_urls,
        bool with_dynamic_discovery,
        const std::filesystem::path& data_dir_path,
        std::function<EccKeyPair()> node_key,
        std::function<EnodeUrl()> node_url,
        uint16_t disc_v4_port);
    ~Discovery();

    Discovery(const Discovery&) = delete;
    Discovery& operator=(const Discovery&) = delete;

    Task<void> run();

    Task<std::vector<EnodeUrl>> request_peer_urls(
        size_t max_count,
        std::vector<EnodeUrl> exclude_urls);

    bool is_static_peer_url(const EnodeUrl& peer_url);

    Task<void> on_peer_disconnected(EccPublicKey peer_public_key, bool is_useless);

  private:
    std::unique_ptr<DiscoveryImpl> p_impl_;
};

}  // namespace silkworm::sentry::discovery
