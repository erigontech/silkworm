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
#include <vector>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <silkworm/infra/concurrency/awaitable_future.hpp>
#include <silkworm/sentry/api/api_common/peer_filter.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/message.hpp>

namespace silkworm::sentry::api::router {

class SendMessageCall final {
  public:
    using PeerKeys = std::vector<sentry::common::EccPublicKey>;

    SendMessageCall(
        sentry::common::Message message,
        api_common::PeerFilter peer_filter,
        boost::asio::any_io_executor& executor)
        : message_(std::move(message)),
          peer_filter_(std::move(peer_filter)),
          result_promise_(std::make_shared<concurrency::AwaitablePromise<PeerKeys>>(executor)) {}

    SendMessageCall() = default;

    [[nodiscard]] const sentry::common::Message& message() const { return message_; }
    [[nodiscard]] const api_common::PeerFilter& peer_filter() const { return peer_filter_; }

    boost::asio::awaitable<PeerKeys> result() {
        auto future = result_promise_->get_future();
        co_return (co_await future.get_async());
    }

    void set_result(PeerKeys result) {
        result_promise_->set_value(std::move(result));
    }

  private:
    sentry::common::Message message_;
    api_common::PeerFilter peer_filter_;
    std::shared_ptr<concurrency::AwaitablePromise<PeerKeys>> result_promise_;
};

}  // namespace silkworm::sentry::api::router
