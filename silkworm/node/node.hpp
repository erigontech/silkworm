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

#include <memory>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/node/common/settings.hpp>
#include <silkworm/node/db/mdbx.hpp>
#include <silkworm/node/settings.hpp>
#include <silkworm/node/snapshot/settings.hpp>
#include <silkworm/node/stagedsync/local_client.hpp>
#include <silkworm/sentry/api/common/sentry_client.hpp>
#include <silkworm/sentry/settings.hpp>

namespace silkworm::node {

class NodeImpl;

class Node {
  public:
    Node(Settings& settings,
         std::shared_ptr<sentry::api::SentryClient> sentry_client,
         mdbx::env chaindata_db);
    ~Node();

    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;

    execution::LocalClient& execution_local_client();

    void setup();

    Task<void> run();

  private:
    std::unique_ptr<NodeImpl> p_impl_;
};

}  // namespace silkworm::node
