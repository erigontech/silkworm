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

#include <iostream>

#include <grpcpp/grpcpp.h>

#include <silkworm/interfaces/remote/ethbackend.grpc.pb.h>
#include <silkworm/silkrpc/grpc/util.hpp>

int ethbackend_async(const std::string& target) {
    // Create ETHBACKEND stub using insecure channel to target
    grpc::CompletionQueue queue;
    grpc::Status status;
    void* got_tag;
    bool ok;

    const auto channel = grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
    const auto stub = remote::ETHBACKEND::NewStub(channel);

    // Etherbase
    grpc::ClientContext eb_context;
    const auto eb_reader = stub->PrepareAsyncEtherbase(&eb_context, remote::EtherbaseRequest{}, &queue);

    eb_reader->StartCall();
    std::cout << "ETHBACKEND Etherbase ->\n";
    remote::EtherbaseReply eb_reply;
    eb_reader->Finish(&eb_reply, &status, eb_reader.get());
    bool has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != eb_reader.get()) {
        return -1;
    }
    if (status.ok()) {
        std::cout << "ETHBACKEND Etherbase <- " << status << " address: " << eb_reply.has_address() << "\n";
    } else {
        std::cout << "ETHBACKEND Etherbase <- " << status << "\n";
    }

    // NetVersion
    grpc::ClientContext nv_context;
    const auto nv_reader = stub->PrepareAsyncNetVersion(&nv_context, remote::NetVersionRequest{}, &queue);

    nv_reader->StartCall();
    std::cout << "ETHBACKEND NetVersion ->\n";
    remote::NetVersionReply nv_reply;
    nv_reader->Finish(&nv_reply, &status, nv_reader.get());
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != nv_reader.get()) {
        return -1;
    }
    if (status.ok()) {
        std::cout << "ETHBACKEND NetVersion <- " << status << " id: " << nv_reply.id() << "\n";
    } else {
        std::cout << "ETHBACKEND NetVersion <- " << status << "\n";
    }

    // Version
    grpc::ClientContext v_context;
    const auto v_reader = stub->PrepareAsyncVersion(&v_context, google::protobuf::Empty{}, &queue);

    v_reader->StartCall();
    std::cout << "ETHBACKEND Version ->\n";
    types::VersionReply v_reply;
    v_reader->Finish(&v_reply, &status, v_reader.get());
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != v_reader.get()) {
        return -1;
    }
    if (status.ok()) {
        std::cout << "ETHBACKEND Version <- " << status << " major.minor.patch: " << v_reply.major() << "." << v_reply.minor() << "." << v_reply.patch() << "\n";
    } else {
        std::cout << "ETHBACKEND Version <- " << status << "\n";
    }

    // ProtocolVersion
    grpc::ClientContext pv_context;
    const auto pv_reader = stub->PrepareAsyncProtocolVersion(&pv_context, remote::ProtocolVersionRequest{}, &queue);

    pv_reader->StartCall();
    std::cout << "ETHBACKEND ProtocolVersion ->\n";
    remote::ProtocolVersionReply pv_reply;
    pv_reader->Finish(&pv_reply, &status, pv_reader.get());
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != pv_reader.get()) {
        return -1;
    }
    if (status.ok()) {
        std::cout << "ETHBACKEND ProtocolVersion <- " << status << " id: " << pv_reply.id() << "\n";
    } else {
        std::cout << "ETHBACKEND ProtocolVersion <- " << status << "\n";
    }

    // ClientVersion
    grpc::ClientContext cv_context;
    const auto cv_reader = stub->PrepareAsyncClientVersion(&cv_context, remote::ClientVersionRequest{}, &queue);

    cv_reader->StartCall();
    std::cout << "ETHBACKEND ClientVersion ->\n";
    remote::ClientVersionReply cv_reply;
    cv_reader->Finish(&cv_reply, &status, cv_reader.get());
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != cv_reader.get()) {
        return -1;
    }
    if (status.ok()) {
        std::cout << "ETHBACKEND ClientVersion <- " << status << " nodename: " << cv_reply.nodename() << "\n";
    } else {
        std::cout << "ETHBACKEND ClientVersion <- " << status << "\n";
    }

    return 0;
}
