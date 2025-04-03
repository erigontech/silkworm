// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <vector>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/infra/grpc/server/server.hpp>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>

#include "state_change_collection.hpp"

namespace silkworm::db::kv::grpc::server {

class KvServer : public virtual rpc::Server {
  public:
    KvServer(
        const rpc::ServerSettings& settings,
        datastore::kvdb::ROAccess chaindata,
        StateChangeCollection* state_change_source);

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
    datastore::kvdb::ROAccess chaindata_;

    //! The collector of state changes acting as source of state change notifications
    StateChangeCollection* state_change_source_;
};

}  // namespace silkworm::db::kv::grpc::server
