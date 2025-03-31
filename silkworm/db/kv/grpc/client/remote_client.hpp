// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>
#include <memory>

#include <agrpc/detail/forward.hpp>

#include <silkworm/db/chain/providers.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>

#include "../../api/client.hpp"
#include "../../api/service.hpp"
#include "../../api/state_cache.hpp"

namespace silkworm::db::kv::grpc::client {

class RemoteClientImpl;

struct RemoteClient : public api::Client {
    RemoteClient(
        const rpc::ChannelFactory& create_channel,
        agrpc::GrpcContext& grpc_context,
        api::StateCache* state_cache,
        chain::Providers providers,
        std::function<Task<void>()> on_disconnect = []() -> Task<void> { co_return; });
    RemoteClient(
        std::unique_ptr<::remote::KV::StubInterface> stub,
        agrpc::GrpcContext& grpc_context,
        api::StateCache* state_cache,
        chain::Providers providers,
        std::function<Task<void>()> on_disconnect = []() -> Task<void> { co_return; });
    ~RemoteClient() override;

    std::shared_ptr<api::Service> service() override;

    void set_min_backoff_timeout(const std::chrono::milliseconds& min_timeout);
    void set_max_backoff_timeout(const std::chrono::milliseconds& max_timeout);

  private:
    std::shared_ptr<RemoteClientImpl> p_impl_;
};

}  // namespace silkworm::db::kv::grpc::client
