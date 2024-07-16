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

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/infra/concurrency/awaitable_future.hpp>
#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/infra/concurrency/event_notifier.hpp>
#include <silkworm/sentry/api/common/message_from_peer.hpp>
#include <silkworm/sentry/api/common/message_id_set.hpp>

#include "state_change.hpp"

namespace silkworm::db::kv::api {

using StateChangeChannel = concurrency::Channel<std::optional<StateChangeSet>>;
using StateChangeChannelPtr = std::shared_ptr<StateChangeChannel>;

class StateChangesCall final {
  public:
    using StateChangeChannelPromise = concurrency::AwaitablePromise<StateChangeChannelPtr>;

    StateChangesCall(StateChangeOptions options, const boost::asio::any_io_executor& executor)
        : options_(options),
          channel_promise_(std::make_shared<StateChangeChannelPromise>(executor)),
          unsubscribe_signal_(std::make_shared<concurrency::EventNotifier>(executor)) {}

    StateChangesCall() = default;

    [[nodiscard]] const StateChangeOptions& options() const { return options_; }

    Task<StateChangeChannelPtr> result() {
        auto future = channel_promise_->get_future();
        co_return co_await future.get_async();
    }

    void set_result(StateChangeChannelPtr channel) {
        channel_promise_->set_value(std::move(channel));
    }

    [[nodiscard]] std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal() const {
        return unsubscribe_signal_;
    }

  private:
    StateChangeOptions options_;
    std::shared_ptr<StateChangeChannelPromise> channel_promise_;
    std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal_;
};

}  // namespace silkworm::db::kv::api
