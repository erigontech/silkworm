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

#include <silkworm/core/common/base.hpp>
#include <silkworm/db/mdbx/mdbx.hpp>
#include <silkworm/execution/api/direct_client.hpp>
#include <silkworm/node/settings.hpp>
#include <silkworm/sentry/api/common/sentry_client.hpp>

namespace silkworm::node {

class NodeImpl;

class Node {
  public:
    Node(
        boost::asio::any_io_executor executor,
        Settings& settings,
        std::shared_ptr<sentry::api::SentryClient> sentry_client,
        std::function<BlockNum()> last_pre_validated_block,
        mdbx::env chaindata_env);
    ~Node();

    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;

    execution::api::DirectClient& execution_direct_client();

    Task<void> run();
    Task<void> wait_for_setup();

  private:
    std::unique_ptr<NodeImpl> p_impl_;
};

}  // namespace silkworm::node
