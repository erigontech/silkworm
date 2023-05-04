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

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>

#include "service.hpp"

namespace silkworm::sentry::api::api_common {

struct SentryClient {
    virtual ~SentryClient() = default;

    virtual boost::asio::awaitable<std::shared_ptr<Service>> service() = 0;

    virtual void on_disconnect(std::function<boost::asio::awaitable<void>()> callback) = 0;
    virtual boost::asio::awaitable<void> reconnect() = 0;
};

}  // namespace silkworm::sentry::api::api_common
