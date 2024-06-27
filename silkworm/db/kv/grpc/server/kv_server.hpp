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

#include <silkworm/core/chain/config.hpp>
#include <silkworm/db/mdbx/mdbx.hpp>
#include <silkworm/infra/grpc/server/server.hpp>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>

#include "state_change_collection.hpp"

namespace silkworm::db::kv::grpc::server {

class KvServer : public virtual rpc::Server {
  public:
    KvServer(const rpc::ServerSettings& settings, mdbx::env* chaindata_env, StateChangeCollection* state_change_source);

    KvServer(const KvServer&) = delete;
    KvServer& operator=(const KvServer&) = delete;

  protected:
    void register_async_services(::grpc::ServerBuilder& builder) override;
    void register_request_calls() override;

  private:
    static void setup_kv_calls();
    void register_kv_request_calls(agrpc::GrpcContext* grpc_context);

    //! \warning The gRPC service must exist for the lifetime of the gRPC server it is registered on.
    remote::KV::AsyncService kv_async_service_;

    //! The chain database environment
    mdbx::env* chaindata_env_;

    //! The collector of state changes acting as source of state change notifications
    StateChangeCollection* state_change_source_;
};

}  // namespace silkworm::db::kv::grpc::server
