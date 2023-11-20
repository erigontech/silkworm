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

#include <functional>
#include <memory>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/enode_url.hpp>
#include <silkworm/sentry/discovery/enr/enr_record.hpp>
#include <silkworm/sentry/discovery/node_db/node_db.hpp>

namespace silkworm::sentry::discovery::disc_v4 {

class DiscoveryImpl;

class Discovery {
  public:
    Discovery(
        const boost::asio::any_io_executor& executor,
        uint16_t server_port,
        std::function<EccKeyPair()> node_key,
        std::function<EnodeUrl()> node_url,
        std::function<discovery::enr::EnrRecord()> node_record,
        node_db::NodeDb& node_db);
    ~Discovery();

    Discovery(const Discovery&) = delete;
    Discovery& operator=(const Discovery&) = delete;

    Task<void> run();

    void discover_more_needed();

  private:
    std::unique_ptr<DiscoveryImpl> p_impl_;
};

}  // namespace silkworm::sentry::discovery::disc_v4
