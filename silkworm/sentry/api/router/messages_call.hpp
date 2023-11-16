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
#include <optional>
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/infra/concurrency/awaitable_future.hpp>
#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/infra/concurrency/event_notifier.hpp>
#include <silkworm/sentry/api/common/message_from_peer.hpp>
#include <silkworm/sentry/api/common/message_id_set.hpp>

namespace silkworm::sentry::api::router {

class MessagesCall final {
  public:
    using TResult = std::shared_ptr<concurrency::Channel<MessageFromPeer>>;

    MessagesCall(
        MessageIdSet message_id_filter,
        const boost::asio::any_io_executor& executor)
        : message_id_filter_(std::move(message_id_filter)),
          result_promise_(std::make_shared<concurrency::AwaitablePromise<TResult>>(executor)),
          unsubscribe_signal_(std::make_shared<concurrency::EventNotifier>(executor)) {}

    MessagesCall() = default;

    [[nodiscard]] const MessageIdSet& message_id_filter() const { return message_id_filter_; }

    Task<TResult> result() {
        auto future = result_promise_->get_future();
        co_return (co_await future.get_async());
    }

    void set_result(TResult result) {
        result_promise_->set_value(std::move(result));
    }

    [[nodiscard]] std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal() const {
        return unsubscribe_signal_;
    }

  private:
    MessageIdSet message_id_filter_;
    std::shared_ptr<concurrency::AwaitablePromise<TResult>> result_promise_;
    std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal_;
};

}  // namespace silkworm::sentry::api::router
