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

#include "service.hpp"
#include "service_router.hpp"

namespace silkworm::db::kv::api {

//! Straightforward asynchronous implementation of KV API service relying on \code Domains.
//! This is used both client-side by 'direct' (i.e. no-gRPC) implementation and server-side by gRPC server.
class DirectService : public Service {
  public:
    explicit DirectService(ServiceRouter router) : router_(router) {}
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

    /** Temporal Point Queries **/

    // rpc HistoryGet(HistoryGetReq) returns (HistoryGetReply);
    Task<HistoryPointResult> get_history(const HistoryPointQuery&) override;

    // rpc DomainGet(DomainGetReq) returns (DomainGetReply);
    Task<DomainPointResult> get_domain(const DomainPointQuery&) override;

    /** Temporal Range Queries **/

    // rpc IndexRange(IndexRangeReq) returns (IndexRangeReply);
    Task<IndexRangeResult> get_index_range(const IndexRangeQuery&) override;

    // rpc HistoryRange(HistoryRangeReq) returns (Pairs);
    Task<HistoryRangeResult> get_history_range(const HistoryRangeQuery&) override;

    // rpc DomainRange(DomainRangeReq) returns (Pairs);
    Task<DomainRangeResult> get_domain_range(const DomainRangeQuery&) override;

  private:
    ServiceRouter router_;
};

}  // namespace silkworm::db::kv::api
