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

#include "kv_factories.hpp"

#include <silkworm/common/log.hpp>

namespace silkworm::rpc {

KvVersionFactory::KvVersionFactory()
    : KvVersionRpcFactory(
        [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
        &remote::KV::AsyncService::RequestVersion) {
    response_.set_major(std::get<0>(kKvApiVersion));
    response_.set_minor(std::get<1>(kKvApiVersion));
    response_.set_patch(std::get<2>(kKvApiVersion));
}

void KvVersionFactory::process_rpc(KvVersionRpc& rpc, const google::protobuf::Empty* request) {
    SILK_TRACE << "KvVersionFactory::process_rpc rpc: " << &rpc << " request: " << request;

    const bool sent = rpc.send_response(response_);

    SILK_TRACE << "KvVersionFactory::process_rpc rsp: " << &response_ << " sent: " << sent;
}

TxFactory::TxFactory()
    : TxRpcFactory(
        [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
        &remote::KV::AsyncService::RequestTx) {
}

void TxFactory::process_rpc(TxRpc& rpc, const remote::Cursor* request) {
    SILK_TRACE << "TxFactory::process_rpc rpc: " << &rpc << " request: " << request << " START";

    if (request == nullptr) {
        // The client has closed its stream of requests, we can close too.
        const bool closed = rpc.close();
        SILK_TRACE << "TxFactory::process_rpc " << &rpc << " closed: " << closed;
    } else {
        handle_request(rpc, request);
    }

    SILK_TRACE << "TxFactory::process_rpc rpc: " << &rpc << " request: " << request << " END";
}

void TxFactory::handle_request(TxRpc& rpc, const remote::Cursor* request) {
    // TODO(canepat): remove this example and fill the correct stream responses
    const auto cursor_op = request->op();
    if (cursor_op == remote::Op::OPEN) {
        remote::Pair kv_pair;
        kv_pair.set_txid(1);
        kv_pair.set_cursorid(1);
        SILK_INFO << "Tx peer: " << rpc.peer() << " op=" << remote::Op_Name(cursor_op) << " cursor=" << kv_pair.cursorid();
        const bool sent = rpc.send_response(kv_pair);
        SILK_TRACE << "TxFactory::handle_request open cursor: " << kv_pair.cursorid() << " sent: " << sent;
    } else if (cursor_op == remote::Op::CLOSE) {
        SILK_INFO << "Tx peer: " << rpc.peer() << " op=" << remote::Op_Name(cursor_op) << " cursor=" << request->cursor();
        const bool sent = rpc.send_response(remote::Pair{});
        SILK_TRACE << "TxFactory::handle_request close cursor: " << request->cursor() << " sent: " << sent;
    } else {
        SILK_INFO << "Tx peer: " << rpc.peer() << " op=" << remote::Op_Name(cursor_op) << " cursor=" << request->cursor();
        remote::Pair kv_pair;
        const bool sent = rpc.send_response(kv_pair);
        SILK_TRACE << "TxFactory::handle_request cursor: " << request->cursor() << " sent: " << sent;
    }
}

StateChangesFactory::StateChangesFactory()
    : StateChangesRpcFactory(
        [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
        &remote::KV::AsyncService::RequestStateChanges) {
}

void StateChangesFactory::process_rpc(StateChangesRpc& rpc, const remote::StateChangeRequest* request) {
    SILK_TRACE << "StateChangesFactory::process_rpc rpc: " << &rpc << " request: " << request;

    // TODO(canepat): remove this example and fill the correct stream responses
    remote::StateChangeBatch response1;
    rpc.send_response(response1);
    remote::StateChangeBatch response2;
    rpc.send_response(response2);

    const bool closed = rpc.close();

    SILK_TRACE << "StateChangesFactory::process_rpc closed: " << closed;
}

} // namespace silkworm::rpc
