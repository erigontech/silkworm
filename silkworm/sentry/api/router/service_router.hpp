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

#include <functional>
#include <optional>

#include <silkworm/infra/concurrency/awaitable_future.hpp>
#include <silkworm/infra/concurrency/channel.hpp>
#include <silkworm/sentry/api/common/node_info.hpp>
#include <silkworm/sentry/api/common/peer_info.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/eth/status_data.hpp>

#include "messages_call.hpp"
#include "peer_call.hpp"
#include "peer_events_call.hpp"
#include "send_message_call.hpp"

namespace silkworm::sentry::api::router {

struct ServiceRouter {
    uint8_t eth_version;

    template <typename T>
    using Channel = concurrency::Channel<T>;

    Channel<eth::StatusData>& status_channel;

    Channel<SendMessageCall>& send_message_channel;
    Channel<MessagesCall>& message_calls_channel;

    Channel<std::shared_ptr<concurrency::AwaitablePromise<size_t>>>& peer_count_calls_channel;
    Channel<std::shared_ptr<concurrency::AwaitablePromise<PeerInfos>>>& peers_calls_channel;
    Channel<PeerCall>& peer_calls_channel;
    Channel<std::optional<sentry::EccPublicKey>>& peer_penalize_calls_channel;
    Channel<PeerEventsCall>& peer_events_calls_channel;

    std::function<NodeInfo()> node_info_provider;
};

}  // namespace silkworm::sentry::api::router
