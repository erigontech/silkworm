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

#include <silkworm/infra/concurrency/awaitable_future.hpp>
#include <silkworm/sentry/api/common/peer_info.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::api::router {

struct PeerCall {
    std::optional<sentry::EccPublicKey> peer_public_key;
    std::shared_ptr<concurrency::AwaitablePromise<std::optional<PeerInfo>>> result_promise;

    PeerCall() = default;

    PeerCall(
        sentry::EccPublicKey peer_public_key1,
        const boost::asio::any_io_executor& executor)
        : peer_public_key(std::move(peer_public_key1)),
          result_promise(std::make_shared<concurrency::AwaitablePromise<std::optional<PeerInfo>>>(executor)) {}
};

}  // namespace silkworm::sentry::api::router
