/*
   Copyright 2024 The Silkworm Authors

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
