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

#include "kv_calls.hpp"

#include <silkworm/common/log.hpp>

namespace silkworm::rpc {

types::VersionReply KvVersionCall::response_;

static auto max_schema_vs_api_version() {
    uint32_t db_schema_major = std::get<0>(kDbSchemaVersion);
    uint32_t db_schema_minor = std::get<1>(kDbSchemaVersion);
    uint32_t kv_api_major = std::get<0>(kKvApiVersion);
    uint32_t kv_api_minor = std::get<1>(kKvApiVersion);
    if (kv_api_major > db_schema_major) {
        return kKvApiVersion;
    }
    if (db_schema_major > kv_api_major) {
        return kDbSchemaVersion;
    }
    if (kv_api_minor > db_schema_minor) {
        return kKvApiVersion;
    }
    if (db_schema_minor > kv_api_minor) {
        return kDbSchemaVersion;
    }
    return kDbSchemaVersion;
}

void KvVersionCall::fill_predefined_reply() {
    const auto max_version = max_schema_vs_api_version();
    KvVersionCall::response_.set_major(std::get<0>(max_version));
    KvVersionCall::response_.set_minor(std::get<1>(max_version));
    KvVersionCall::response_.set_patch(std::get<2>(max_version));
}

KvVersionCall::KvVersionCall(remote::KV::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
    : UnaryRpc<remote::KV::AsyncService, google::protobuf::Empty, types::VersionReply>(service, queue, handlers) {
}

void KvVersionCall::process(const google::protobuf::Empty* request) {
    SILK_TRACE << "KvVersionCall::process " << this << " request: " << request;

    const bool sent = send_response(response_);

    SILK_TRACE << "KvVersionCall::process " << this << " rsp: " << &response_ << " sent: " << sent;
}

KvVersionCallFactory::KvVersionCallFactory()
    : CallFactory<remote::KV::AsyncService, KvVersionCall>(&remote::KV::AsyncService::RequestVersion) {
    KvVersionCall::fill_predefined_reply();
}

TxCall::TxCall(remote::KV::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
    : BidirectionalStreamingRpc<remote::KV::AsyncService, remote::Cursor, remote::Pair>(service, queue, handlers) {
}

void TxCall::process(const remote::Cursor* request) {
    SILK_TRACE << "TxCall::process " << this << " request: " << request << " START";

    if (request == nullptr) {
        // The client has closed its stream of requests, we can close too.
        const bool closed = close();
        SILK_TRACE << "TxCall::process " << this << " closed: " << closed;
    } else {
        // TODO(canepat): remove this example and fill the correct stream responses
        const auto cursor_op = request->op();
        if (cursor_op == remote::Op::OPEN) {
            remote::Pair kv_pair;
            kv_pair.set_txid(1);
            kv_pair.set_cursorid(1);
            SILK_INFO << "Tx peer: " << peer() << " op=" << remote::Op_Name(cursor_op) << " cursor=" << kv_pair.cursorid();
            const bool sent = send_response(kv_pair);
            SILK_TRACE << "TxFactory::process " << this << " open cursor: " << kv_pair.cursorid() << " sent: " << sent;
        } else if (cursor_op == remote::Op::CLOSE) {
            SILK_INFO << "Tx peer: " << peer() << " op=" << remote::Op_Name(cursor_op) << " cursor=" << request->cursor();
            const bool sent = send_response(remote::Pair{});
            SILK_TRACE << "TxFactory::process " << this << " close cursor: " << request->cursor() << " sent: " << sent;
        } else {
            SILK_INFO << "Tx peer: " << peer() << " op=" << remote::Op_Name(cursor_op) << " cursor=" << request->cursor();
            remote::Pair kv_pair;
            const bool sent = send_response(kv_pair);
            SILK_TRACE << "TxFactory::process " << this << " cursor: " << request->cursor() << " sent: " << sent;
        }
    }

    SILK_TRACE << "TxCall::process " << this << " request: " << request << " END";
}

TxCallFactory::TxCallFactory(const EthereumBackEnd& backend)
    : CallFactory<remote::KV::AsyncService, TxCall>(&remote::KV::AsyncService::RequestTx),
    chaindata_env_(backend.chaindata_env()) {
}

StateChangesCall::StateChangesCall(remote::KV::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
    : ServerStreamingRpc<remote::KV::AsyncService, remote::StateChangeRequest, remote::StateChangeBatch>(service, queue, handlers) {
}

void StateChangesCall::process(const remote::StateChangeRequest* request) {
    SILK_TRACE << "StateChangesCall::process " << this << " request: " << request;

    // TODO(canepat): remove this example and fill the correct stream responses
    remote::StateChangeBatch response1;
    send_response(response1);
    remote::StateChangeBatch response2;
    send_response(response2);

    const bool closed = close();

    SILK_TRACE << "StateChangesCall::process " << this << " closed: " << closed;
}

StateChangesCallFactory::StateChangesCallFactory()
    : CallFactory<remote::KV::AsyncService, StateChangesCall>(&remote::KV::AsyncService::RequestStateChanges) {
}

KvService::KvService(const EthereumBackEnd& backend) : tx_factory_{backend} {
}

void KvService::register_kv_request_calls(remote::KV::AsyncService* async_service, grpc::ServerCompletionQueue* queue) {
    // Register one requested call for each RPC factory
    kv_version_factory_.create_rpc(async_service, queue);
    tx_factory_.create_rpc(async_service, queue);
    state_changes_factory_.create_rpc(async_service, queue);
}

} // namespace silkworm::rpc
