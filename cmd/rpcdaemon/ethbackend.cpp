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

#include <iomanip>
#include <iostream>
#include <string>

#include <grpcpp/grpcpp.h>

#include <silkworm/interfaces/remote/ethbackend.grpc.pb.h>
#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/silkrpc/grpc/util.hpp>

inline std::ostream& operator<<(std::ostream& out, const types::H160& address) {
    out << "address=" << address.has_hi();
    if (address.has_hi()) {
        auto& hi_half = address.hi();
        out << std::hex << hi_half.hi() << hi_half.lo();
    } else {
        auto lo_half = address.lo();
        out << std::hex << lo_half;
    }
    out << std::dec;
    return out;
}

int ethbackend(const std::string& target) {
    // Create ETHBACKEND stub using insecure channel to target
    grpc::Status status;

    const auto channel = grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
    const auto stub = remote::ETHBACKEND::NewStub(channel);

    grpc::ClientContext eb_context;
    remote::EtherbaseReply eb_reply;
    std::cout << "ETHBACKEND Etherbase ->\n";
    status = stub->Etherbase(&eb_context, remote::EtherbaseRequest{}, &eb_reply);
    if (status.ok()) {
        std::cout << "ETHBACKEND Etherbase <- " << status << " address: " << eb_reply.address() << "\n";
    } else {
        std::cout << "ETHBACKEND Etherbase <- " << status << "\n";
    }

    grpc::ClientContext nv_context;
    remote::NetVersionReply nv_reply;
    std::cout << "ETHBACKEND NetVersion ->\n";
    status = stub->NetVersion(&nv_context, remote::NetVersionRequest{}, &nv_reply);
    if (status.ok()) {
        std::cout << "ETHBACKEND NetVersion <- " << status << " id: " << nv_reply.id() << "\n";
    } else {
        std::cout << "ETHBACKEND NetVersion <- " << status << "\n";
    }

    grpc::ClientContext v_context;
    types::VersionReply v_reply;
    std::cout << "ETHBACKEND Version ->\n";
    status = stub->Version(&v_context, google::protobuf::Empty{}, &v_reply);
    if (status.ok()) {
        std::cout << "ETHBACKEND Version <- " << status << " major.minor.patch: " << v_reply.major() << "." << v_reply.minor() << "." << v_reply.patch() << "\n";
    } else {
        std::cout << "ETHBACKEND Version <- " << status << "\n";
    }

    grpc::ClientContext pv_context;
    remote::ProtocolVersionReply pv_reply;
    std::cout << "ETHBACKEND ProtocolVersion ->\n";
    status = stub->ProtocolVersion(&pv_context, remote::ProtocolVersionRequest{}, &pv_reply);
    if (status.ok()) {
        std::cout << "ETHBACKEND ProtocolVersion <- " << status << " id: " << pv_reply.id() << "\n";
    } else {
        std::cout << "ETHBACKEND ProtocolVersion <- " << status << "\n";
    }

    grpc::ClientContext cv_context;
    remote::ClientVersionReply cv_reply;
    std::cout << "ETHBACKEND ClientVersion ->\n";
    status = stub->ClientVersion(&cv_context, remote::ClientVersionRequest{}, &cv_reply);
    if (status.ok()) {
        std::cout << "ETHBACKEND ClientVersion <- " << status << " node name: " << cv_reply.node_name() << "\n";
    } else {
        std::cout << "ETHBACKEND ClientVersion <- " << status << "\n";
    }

    return 0;
}
