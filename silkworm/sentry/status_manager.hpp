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

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/sentry/common/atomic_value.hpp>

#include "eth/status_data.hpp"

namespace silkworm::sentry {

class StatusManager {
  public:
    StatusManager(const boost::asio::any_io_executor& executor)
        : status_channel_(executor),
          status_(eth::StatusData{}) {}

    Task<void> wait_for_status();

    Task<void> run();

    concurrency::Channel<eth::StatusData>& status_channel() {
        return status_channel_;
    }

    std::function<eth::StatusData()> status_provider() {
        return status_.getter();
    }

  private:
    concurrency::Channel<eth::StatusData> status_channel_;
    AtomicValue<eth::StatusData> status_;
};

}  // namespace silkworm::sentry
