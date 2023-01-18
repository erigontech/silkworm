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
#include <set>
#include <utility>
#include <variant>

#include <silkworm/concurrency/coroutine.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <silkworm/sentry/common/channel.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/message.hpp>

namespace silkworm::sentry::rpc::common {

class MessagesCall final {
  public:
    struct MessageFromPeer {
        sentry::common::Message message;
        std::optional<sentry::common::EccPublicKey> peer_public_key;
    };

    using MessageIdSet = std::set<uint8_t>;
    using TResult = std::shared_ptr<sentry::common::Channel<MessageFromPeer>>;

    MessagesCall(
        MessageIdSet message_id_filter,
        boost::asio::any_io_executor& executor)
        : message_id_filter_(std::move(message_id_filter)),
          result_channel_(std::make_shared<sentry::common::Channel<TResult>>(executor)),
          unsubscribe_signal_channel_(std::make_shared<sentry::common::Channel<std::monostate>>(executor)) {}

    MessagesCall() = default;

    [[nodiscard]] const MessageIdSet& message_id_filter() const { return message_id_filter_; }

    boost::asio::awaitable<TResult> result() {
        return result_channel_->receive();
    }

    boost::asio::awaitable<void> set_result(TResult result) {
        co_await result_channel_->send(std::move(result));
    }

    [[nodiscard]] std::shared_ptr<sentry::common::Channel<std::monostate>> unsubscribe_signal_channel() const {
        return unsubscribe_signal_channel_;
    }

  private:
    MessageIdSet message_id_filter_;
    std::shared_ptr<sentry::common::Channel<TResult>> result_channel_;
    std::shared_ptr<sentry::common::Channel<std::monostate>> unsubscribe_signal_channel_;
};

}  // namespace silkworm::sentry::rpc::common
