/*
   Copyright 2020-2022 The Silkrpc Authors

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

#include "version.hpp"

#include <sstream>
#include <type_traits>

namespace silkrpc {

std::ostream& operator<<(std::ostream& out, const ProtocolVersion& v) {
    out << v.major << "." << v.minor << "." << v.patch;
    return out;
}

template<typename StubInterface>
ProtocolVersionResult wait_for_protocol_check(const std::unique_ptr<StubInterface>& stub, const ProtocolVersion& version, const std::string& name) {
    grpc::ClientContext context;
    context.set_wait_for_ready(true);

    types::VersionReply version_reply;
    const auto status = stub->Version(&context, google::protobuf::Empty{}, &version_reply);
    if (!status.ok()) {
        return ProtocolVersionResult{false, name + " incompatible interface: " + status.error_message() + " [" + status.error_details() + "]"};
    }
    ProtocolVersion server_version{version_reply.major(), version_reply.minor(), version_reply.patch()};

    std::stringstream vv_stream;
    vv_stream << "client=" << version << " server=" << server_version;
    if (version.major != server_version.major) {
        return ProtocolVersionResult{false, name + " incompatible interface: " + vv_stream.str()};
    } else if (version.minor != server_version.minor) {
        return ProtocolVersionResult{false, name + " incompatible interface: " + vv_stream.str()};
    } else {
        return ProtocolVersionResult{true, name + " compatible interface: " + vv_stream.str()};
    }
}

template<auto Func, typename StubInterface>
struct NewStubFactory final {
    auto operator()(const std::shared_ptr<grpc::ChannelInterface>& channel, const grpc::StubOptions& options = grpc::StubOptions()) -> std::unique_ptr<StubInterface> {
        return std::invoke(Func, channel, options);
    }
};

ProtocolVersionResult wait_for_kv_protocol_check(const std::unique_ptr<::remote::KV::StubInterface>& stub) {
    return wait_for_protocol_check(stub, KV_SERVICE_API_VERSION, "KV");
}

ProtocolVersionResult wait_for_kv_protocol_check(const std::shared_ptr<grpc::Channel>& channel) {
    NewStubFactory<::remote::KV::NewStub, ::remote::KV::StubInterface> new_stub_factory;
    return wait_for_protocol_check(new_stub_factory(channel), KV_SERVICE_API_VERSION, "KV");
}

ProtocolVersionResult wait_for_ethbackend_protocol_check(const std::unique_ptr<::remote::ETHBACKEND::StubInterface>& stub) {
    return wait_for_protocol_check(stub, ETHBACKEND_SERVICE_API_VERSION, "ETHBACKEND");
}

ProtocolVersionResult wait_for_ethbackend_protocol_check(const std::shared_ptr<grpc::Channel>& channel) {
    NewStubFactory<::remote::ETHBACKEND::NewStub, ::remote::ETHBACKEND::StubInterface> new_stub_factory;
    return wait_for_protocol_check(new_stub_factory(channel), ETHBACKEND_SERVICE_API_VERSION, "ETHBACKEND");
}

ProtocolVersionResult wait_for_mining_protocol_check(const std::unique_ptr<::txpool::Mining::StubInterface>& stub) {
    return wait_for_protocol_check(stub, MINING_SERVICE_API_VERSION, "MINING");
}

ProtocolVersionResult wait_for_mining_protocol_check(const std::shared_ptr<grpc::Channel>& channel) {
    NewStubFactory<::txpool::Mining::NewStub, ::txpool::Mining::StubInterface> new_stub_factory;
    return wait_for_protocol_check(new_stub_factory(channel), MINING_SERVICE_API_VERSION, "MINING");
}

ProtocolVersionResult wait_for_txpool_protocol_check(const std::unique_ptr<::txpool::Txpool::StubInterface>& stub) {
    return wait_for_protocol_check(stub, TXPOOL_SERVICE_API_VERSION, "TXPOOL");
}

ProtocolVersionResult wait_for_txpool_protocol_check(const std::shared_ptr<grpc::Channel>& channel) {
    NewStubFactory<::txpool::Txpool::NewStub, ::txpool::Txpool::StubInterface> new_stub_factory;
    return wait_for_protocol_check(new_stub_factory(channel), TXPOOL_SERVICE_API_VERSION, "TXPOOL");
}

} // namespace silkrpc
