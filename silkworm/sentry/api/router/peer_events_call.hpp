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

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/infra/concurrency/awaitable_future.hpp>
#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/infra/concurrency/event_notifier.hpp>
#include <silkworm/sentry/api/common/peer_event.hpp>

namespace silkworm::sentry::api::router {

struct PeerEventsCall {
    using TResult = std::shared_ptr<concurrency::Channel<PeerEvent>>;

    std::shared_ptr<concurrency::AwaitablePromise<TResult>> result_promise;
    std::shared_ptr<concurrency::EventNotifier> unsubscribe_signal;

    PeerEventsCall() = default;

    explicit PeerEventsCall(const boost::asio::any_io_executor& executor)
        : result_promise(std::make_shared<concurrency::AwaitablePromise<TResult>>(executor)),
          unsubscribe_signal(std::make_shared<concurrency::EventNotifier>(executor)) {}
};

}  // namespace silkworm::sentry::api::router
