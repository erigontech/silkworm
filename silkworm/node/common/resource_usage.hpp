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

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/steady_timer.hpp>

#include <silkworm/node/common/settings.hpp>

namespace silkworm {

//! Log for resource usage
class ResourceUsageLog {
  public:
    explicit ResourceUsageLog(NodeSettings& settings);

    Task<void> run();

  private:
    NodeSettings& settings_;
    boost::asio::steady_timer timer_;
};

}  // namespace silkworm
