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

#include <functional>
#include <memory>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/infra/concurrency/executor_pool.hpp>

#include "api/common/sentry_client.hpp"
#include "settings.hpp"

struct buildinfo;

namespace silkworm::sentry {

class SentryImpl;

class Sentry final : public api::SentryClient {
  public:
    explicit Sentry(Settings settings, concurrency::ExecutorPool& executor_pool);
    ~Sentry() override;

    Sentry(const Sentry&) = delete;
    Sentry& operator=(const Sentry&) = delete;

    Task<void> run();

    Task<std::shared_ptr<api::Service>> service() override;
    [[nodiscard]] bool is_ready() override;
    void on_disconnect(std::function<Task<void>()> callback) override;
    Task<void> reconnect() override;

    static std::string make_client_id(const buildinfo& info);

  private:
    std::unique_ptr<SentryImpl> p_impl_;
};

}  // namespace silkworm::sentry
