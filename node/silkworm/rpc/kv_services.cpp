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

#include "kv_services.hpp"

#include <silkworm/common/log.hpp>

namespace silkworm::rpc {

KvVersionService::KvVersionService()
    : KvVersionRpcService(
        [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
        &remote::KV::AsyncService::RequestVersion) {
    response_.set_major(std::get<0>(kKvApiVersion));
    response_.set_minor(std::get<1>(kKvApiVersion));
    response_.set_patch(std::get<2>(kKvApiVersion));
}

void KvVersionService::process_rpc(KvVersionRpc& rpc, const google::protobuf::Empty* request) {
    SILK_TRACE << "KvVersionService::process_rpc rpc: " << &rpc << " request: " << request;

    const bool sent = rpc.send_response(response_);

    SILK_TRACE << "KvVersionService::process_rpc rsp: " << &response_ << " sent: " << sent;
}

void TxService::process_rpc(TxRpc& rpc, const remote::Cursor* request) {
    SILK_TRACE << "TxService::process_rpc rpc: " << &rpc << " request: " << request;

    // TODO(canepat): remove this example and fill the correct stream responses
    remote::Pair response1;
    rpc.send_response(response1);
    remote::Pair response2;
    rpc.send_response(response2);

    const bool closed = rpc.close();

    SILK_TRACE << "TxService::process_rpc closed: " << closed;
}

void StateChangesService::process_rpc(StateChangesRpc& rpc, const remote::StateChangeRequest* request) {
    SILK_TRACE << "StateChangesService::process_rpc rpc: " << &rpc << " request: " << request;

    // TODO(canepat): remove this example and fill the correct stream responses
    remote::StateChangeBatch response1;
    rpc.send_response(response1);
    remote::StateChangeBatch response2;
    rpc.send_response(response2);

    const bool closed = rpc.close();

    SILK_TRACE << "StateChangesService::process_rpc closed: " << closed;
}

} // namespace silkworm::rpc
