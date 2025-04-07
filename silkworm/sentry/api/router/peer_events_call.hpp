// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/infra/concurrency/awaitable_future.hpp>
#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/infra/concurrency/event_notifier.hpp>
#include <silkworm/sentry/api/common/peer_event.hpp>

namespace silkworm::sentry::api::router {

struct PeerEventsCall {
    using Result = std::shared_ptr<concurrency::Channel<PeerEvent>>;

    std::shared_ptr<concurrency::AwaitablePromise<Result>> result_promise;
    std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal;

    PeerEventsCall() = default;

    explicit PeerEventsCall(const boost::asio::any_io_executor& executor)
        : result_promise(std::make_shared<concurrency::AwaitablePromise<Result>>(executor)),
          unsubscribe_signal(std::make_shared<concurrency::EventNotifier>(executor)) {}
};

}  // namespace silkworm::sentry::api::router
