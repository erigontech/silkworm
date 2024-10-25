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
#include <vector>

#include <silkworm/sentry/api/common/sentry_client.hpp>

namespace silkworm::sentry {

class MultiSentryClientImpl;

class MultiSentryClient : public api::SentryClient {
  public:
    explicit MultiSentryClient(std::vector<std::shared_ptr<api::SentryClient>> clients);
    ~MultiSentryClient() override;

    Task<std::shared_ptr<api::Service>> service() override;

    bool is_ready() override;
    void on_disconnect(std::function<Task<void>()> callback) override;
    Task<void> reconnect() override;

  private:
    std::shared_ptr<MultiSentryClientImpl> p_impl_;
};

}  // namespace silkworm::sentry
