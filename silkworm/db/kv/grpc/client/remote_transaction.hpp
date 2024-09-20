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

#include <map>
#include <memory>
#include <string>
#include <type_traits>

#include <silkworm/infra/concurrency/task.hpp>

#include <agrpc/client_rpc.hpp>
#include <agrpc/grpc_context.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/db/chain/remote_chain_storage.hpp>
#include <silkworm/db/kv/api/base_transaction.hpp>
#include <silkworm/db/kv/api/cursor.hpp>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>

#include "remote_cursor.hpp"
#include "rpc.hpp"

namespace silkworm::db::kv::grpc::client {

class RemoteTransaction : public api::BaseTransaction {
  public:
    RemoteTransaction(::remote::KV::StubInterface& stub,
                      agrpc::GrpcContext& grpc_context,
                      api::StateCache* state_cache,
                      chain::BlockProvider block_provider,
                      chain::BlockNumberFromTxnHashProvider block_number_from_txn_hash_provider);
    ~RemoteTransaction() override = default;

    uint64_t tx_id() const override { return tx_id_; }
    uint64_t view_id() const override { return view_id_; }

    Task<void> open() override;

    Task<std::shared_ptr<api::Cursor>> cursor(const std::string& table) override;

    Task<std::shared_ptr<api::CursorDupSort>> cursor_dup_sort(const std::string& table) override;

    std::shared_ptr<silkworm::State> create_state(boost::asio::any_io_executor& executor, const chain::ChainStorage& storage, BlockNum block_number) override;

    std::shared_ptr<chain::ChainStorage> create_storage() override;

    Task<void> close() override;

    // rpc DomainGet(DomainGetReq) returns (DomainGetReply);
    Task<api::DomainPointResult> domain_get(api::DomainPointQuery&&) override;

    // rpc HistorySeek(HistorySeekReq) returns (HistorySeekReply);
    Task<api::HistoryPointResult> history_seek(api::HistoryPointQuery&& query) override;

    // rpc IndexRange(IndexRangeReq) returns (IndexRangeReply);
    Task<api::PaginatedTimestamps> index_range(api::IndexRangeQuery&& query) override;

    // rpc HistoryRange(HistoryRangeReq) returns (Pairs);
    Task<api::PaginatedKeysValues> history_range(api::HistoryRangeQuery&& query) override;

    // rpc DomainRange(DomainRangeReq) returns (Pairs);
    Task<api::PaginatedKeysValues> domain_range(api::DomainRangeQuery&& query) override;

  private:
    Task<std::shared_ptr<api::CursorDupSort>> get_cursor(const std::string& table, bool is_cursor_dup_sort);

    chain::BlockProvider block_provider_;
    chain::BlockNumberFromTxnHashProvider block_number_from_txn_hash_provider_;
    std::map<std::string, std::shared_ptr<api::CursorDupSort>> cursors_;
    std::map<std::string, std::shared_ptr<api::CursorDupSort>> dup_cursors_;
    ::remote::KV::StubInterface& stub_;
    agrpc::GrpcContext& grpc_context_;
    //! The wrapped Tx RPC client provided by agrpc
    TxRpc tx_rpc_;
    //! Flag indicating if agrpc::ClientRPC<>::start has been called on Tx RPC or not. This is necessary to avoid
    //! a crash in agrpc if you call agrpc::ClientRPC<>::finish before calling agrpc::ClientRPC<>::start
    bool start_called_{false};
    uint64_t tx_id_{0};
    uint64_t view_id_{0};
};

}  // namespace silkworm::db::kv::grpc::client
