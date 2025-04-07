// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/infra/concurrency/awaitable_future.hpp>
#include <silkworm/sentry/api/common/peer_filter.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/message.hpp>

namespace silkworm::sentry::api::router {

class SendMessageCall final {
  public:
    using PeerKeys = std::vector<sentry::EccPublicKey>;

    SendMessageCall(
        sentry::Message message,
        PeerFilter peer_filter,
        const boost::asio::any_io_executor& executor)
        : message_(std::move(message)),
          peer_filter_(std::move(peer_filter)),
          result_promise_(std::make_shared<concurrency::AwaitablePromise<PeerKeys>>(executor)) {}

    SendMessageCall() = default;

    const sentry::Message& message() const { return message_; }
    const PeerFilter& peer_filter() const { return peer_filter_; }

    Task<PeerKeys> result() {
        auto future = result_promise_->get_future();
        co_return (co_await future.get_async());
    }

    void set_result(PeerKeys result) {
        result_promise_->set_value(std::move(result));
    }

  private:
    sentry::Message message_;
    PeerFilter peer_filter_;
    std::shared_ptr<concurrency::AwaitablePromise<PeerKeys>> result_promise_;
};

}  // namespace silkworm::sentry::api::router
