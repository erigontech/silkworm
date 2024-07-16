/*
   Copyright 2024 The Silkworm Authors

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

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <silkworm/infra/concurrency/channel.hpp>

#include "endpoint/state_changes_call.hpp"

namespace silkworm::db::kv::api {

struct ServiceRouter {
    concurrency::Channel<StateChangesCall>& state_changes_calls_channel;
};

class StateChangeRunner {
  public:
    static Task<void> run(std::shared_ptr<StateChangeRunner> self);

    explicit StateChangeRunner(const boost::asio::any_io_executor& executor);

    template <typename T>
    using Channel = concurrency::Channel<T>;

    Channel<StateChangesCall>& state_changes_calls_channel() {
        return state_changes_calls_channel_;
    }

  private:
    Task<void> handle_calls();

    Channel<StateChangesCall> state_changes_calls_channel_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;
};

}  // namespace silkworm::db::kv::api
