/*
   Copyright 2022 The Silkworm Authors

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

#include <silkworm/concurrency/coroutine.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/rpc/server/server_context_pool.hpp>

namespace silkworm::cl {

struct Settings {
    log::Settings log_settings;
    uint32_t num_contexts{1};
    rpc::WaitMode wait_mode{rpc::WaitMode::blocking};
};

class LightClientImpl;

class LightClient {
  public:
    explicit LightClient(Settings settings);
    ~LightClient();

    LightClient(const LightClient&) = delete;
    LightClient& operator=(const LightClient&) = delete;

    void start();
    void stop();
    void join();

  private:
    std::unique_ptr<LightClientImpl> p_impl_;
};

}  // namespace silkworm::cl
