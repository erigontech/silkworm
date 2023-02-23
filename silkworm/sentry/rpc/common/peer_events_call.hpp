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
#include <optional>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/sentry/common/channel.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/common/event_notifier.hpp>
#include <silkworm/sentry/common/promise.hpp>

namespace silkworm::sentry::rpc::common {

struct PeerEventsCall {
    enum class PeerEventId {
        kAdded,
        kRemoved,
    };

    struct PeerEvent {
        std::optional<sentry::common::EccPublicKey> peer_public_key;
        PeerEventId event_id;
    };

    using TResult = std::shared_ptr<sentry::common::Channel<PeerEvent>>;

    std::shared_ptr<sentry::common::Promise<TResult>> result_promise;
    std::shared_ptr<sentry::common::EventNotifier> unsubscribe_signal;

    PeerEventsCall() = default;

    explicit PeerEventsCall(boost::asio::any_io_executor& executor)
        : result_promise(std::make_shared<sentry::common::Promise<TResult>>(executor)),
          unsubscribe_signal(std::make_shared<sentry::common::EventNotifier>(executor)) {}
};

}  // namespace silkworm::sentry::rpc::common
