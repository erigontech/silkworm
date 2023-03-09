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

#include <silkworm/node/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>

#include <silkworm/node/concurrency/channel.hpp>
#include <silkworm/sentry/common/atomic_value.hpp>

#include "eth/status_data.hpp"

namespace silkworm::sentry {

class StatusManager {
  public:
    StatusManager(boost::asio::io_context& io_context)
        : status_channel_(io_context),
          status_(eth::StatusData{}) {}

    boost::asio::awaitable<void> wait_for_status();

    boost::asio::awaitable<void> start();

    concurrency::Channel<eth::StatusData>& status_channel() {
        return status_channel_;
    }

    std::function<eth::StatusData()> status_provider() {
        return status_.getter();
    }

  private:
    concurrency::Channel<eth::StatusData> status_channel_;
    common::AtomicValue<eth::StatusData> status_;
};

}  // namespace silkworm::sentry
