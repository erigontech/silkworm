// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
    using Result = std::shared_ptr<concurrency::Channel<MessageFromPeer>>;

    MessagesCall(
        MessageIdSet message_id_filter,
        const boost::asio::any_io_executor& executor)
        : message_id_filter_(std::move(message_id_filter)),
          result_promise_(std::make_shared<concurrency::AwaitablePromise<Result>>(executor)),
          unsubscribe_signal_(std::make_shared<concurrency::EventNotifier>(executor)) {}

    MessagesCall() = default;

    const MessageIdSet& message_id_filter() const { return message_id_filter_; }

    Task<Result> result() {
        auto future = result_promise_->get_future();
        co_return (co_await future.get_async());
    }

    void set_result(Result result) {
        result_promise_->set_value(std::move(result));
    }

    std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal() const {
        return unsubscribe_signal_;
    }

  private:
    MessageIdSet message_id_filter_;
    std::shared_ptr<concurrency::AwaitablePromise<Result>> result_promise_;
    std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal_;
};

}  // namespace silkworm::sentry::api::router
