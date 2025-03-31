// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/data_store.hpp>

#include "local_transaction.hpp"
#include "service.hpp"
#include "service_router.hpp"

namespace silkworm::db::kv::api {

//! Straightforward asynchronous implementation of KV API service relying on \code Domains.
//! This is used both client-side by 'direct' (i.e. no-gRPC) implementation and server-side by gRPC server.
class DirectService : public Service {
  public:
    DirectService(ServiceRouter router, DataStoreRef data_store, const ChainConfig& chain_config, StateCache* state_cache);
    ~DirectService() override = default;

    DirectService(const DirectService&) = delete;
    DirectService& operator=(const DirectService&) = delete;

    DirectService(DirectService&&) = delete;
    DirectService& operator=(DirectService&&) = delete;

    // rpc Version(google.protobuf.Empty) returns (types.VersionReply);
    Task<Version> version() override;

    // rpc Tx(stream Cursor) returns (stream Pair);
    Task<std::unique_ptr<Transaction>> begin_transaction() override;

    // rpc StateChanges(StateChangeRequest) returns (stream StateChangeBatch);
    Task<void> state_changes(const StateChangeOptions&, StateChangeConsumer) override;

  private:
    //! The router to service endpoint implementation
    ServiceRouter router_;

    //! The data store
    DataStoreRef data_store_;

    //! The chain configuration
    const ChainConfig& chain_config_;

    //! The local state cache built upon incoming state changes
    StateCache* state_cache_;
};

}  // namespace silkworm::db::kv::api
