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

#include "backend_server.hpp"

#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <types/types.pb.h>

namespace silkworm::rpc {

inline types::H128* new_H128_from_bytes(const uint8_t* bytes) {
    auto h128{new types::H128()};
    h128->set_hi(endian::load_big_u64(bytes));
    h128->set_lo(endian::load_big_u64(bytes + 8));
    return h128;
}

inline types::H160* new_H160_address(const evmc::address& address) {
    auto h160{new types::H160()};
    auto hi{new_H128_from_bytes(address.bytes)};
    h160->set_allocated_hi(hi);
    h160->set_lo(endian::load_big_u32(address.bytes + 16));
    return h160;
}

void EtherbaseService::process_rpc(EtherbaseUnaryRpc& rpc, const remote::EtherbaseRequest* request) {
    SILK_TRACE << "EtherbaseService::process_rpc START rpc: " << &rpc << " request: " << request;

    remote::EtherbaseReply response;
    const auto h160 = new_H160_address(etherbase_);
    response.set_allocated_address(h160);
    const bool sent = rpc.send_response(response);

    SILK_TRACE << "EtherbaseService::process_rpc END rsp: " << &response << " etherbase: " << to_hex(etherbase_) << " sent: " << sent;
}

void NetVersionService::process_rpc(NetVersionUnaryRpc& rpc, const remote::NetVersionRequest* request) {
    SILK_TRACE << "NetVersionService::process_rpc rpc: " << &rpc << " request: " << request;

    remote::NetVersionReply response;
    response.set_id(chain_id_);
    const bool sent = rpc.send_response(response);

    SILK_TRACE << "NetVersionService::process_rpc rsp: " << &response << " chain_id: " << chain_id_ << " sent: " << sent;
}

BackEndServer::BackEndServer(const ServerConfig& srv_config, const ChainConfig& chain_config)
: Server(srv_config), etherbase_service_{chain_config}, net_version_service_{chain_config} {
    SILK_INFO << "BackEndServer created listening on: " << srv_config.address_uri();
}

/// Start server-side RPC requests as required by gRPC async model: one RPC per type is requested in advance.
void BackEndServer::request_calls() {
    // Grab one context at a time using round-robin scheme and start each server-side RPC request
    auto& context1 = next_context();
    context1.io_context->post([&]() {
        etherbase_service_.create_rpc(service_.get(), context1.grpc_queue.get());
    });
    auto& context2 = next_context();
    context2.io_context->post([&]() {
        net_version_service_.create_rpc(service_.get(), context2.grpc_queue.get());
    });
}

} // namespace silkworm::rpc
