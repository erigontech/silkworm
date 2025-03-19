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

#include <silkworm/db/data_store.hpp>

#include "service.hpp"
#include "service_router.hpp"

namespace silkworm::db::kv::api {

//! Straightforward asynchronous implementation of KV API service relying on \code Domains.
//! This is used both client-side by 'direct' (i.e. no-gRPC) implementation and server-side by gRPC server.
class DirectService : public Service {
  public:
    DirectService(ServiceRouter router, DataStoreRef data_store);
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
};

}  // namespace silkworm::db::kv::api
