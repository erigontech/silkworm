// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
