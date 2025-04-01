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

#include "version.hpp"

#include <sstream>

namespace silkworm::rpc {

std::ostream& operator<<(std::ostream& out, const ProtocolVersion& v) {
    out << v.to_string();
    return out;
}

std::string ProtocolVersion::to_string() const {
    const auto& v = *this;
    std::stringstream out;

    out << v.major << "." << v.minor << "." << v.patch;
    return out.str();
}

template <typename StubInterface>
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
    if (version.major != server_version.major) {  // NOLINT(bugprone-branch-clone)
        return ProtocolVersionResult{false, name + " incompatible interface: " + vv_stream.str()};
    }
    if (version.minor != server_version.minor) {
        return ProtocolVersionResult{false, name + " incompatible interface: " + vv_stream.str()};
    }
    return ProtocolVersionResult{true, name + " compatible interface: " + vv_stream.str()};
}

template <auto Func, typename StubInterface>
struct NewStubFactory final {
    std::unique_ptr<StubInterface> operator()(const std::shared_ptr<grpc::ChannelInterface>& channel, const grpc::StubOptions& options = grpc::StubOptions()) {
        return std::invoke(Func, channel, options);
    }
};

ProtocolVersionResult wait_for_kv_protocol_check(const std::unique_ptr<::remote::KV::StubInterface>& stub) {
    return wait_for_protocol_check(stub, kKvServiceApiVersion, "KV");
}

ProtocolVersionResult wait_for_kv_protocol_check(const std::shared_ptr<grpc::Channel>& channel) {
    NewStubFactory<::remote::KV::NewStub, ::remote::KV::StubInterface> new_stub_factory;
    return wait_for_protocol_check(new_stub_factory(channel), kKvServiceApiVersion, "KV");
}

ProtocolVersionResult wait_for_ethbackend_protocol_check(const std::unique_ptr<::remote::ETHBACKEND::StubInterface>& stub) {
    return wait_for_protocol_check(stub, kEthBackEndServiceApiVersion, "ETHBACKEND");
}

ProtocolVersionResult wait_for_ethbackend_protocol_check(const std::shared_ptr<grpc::Channel>& channel) {
    NewStubFactory<::remote::ETHBACKEND::NewStub, ::remote::ETHBACKEND::StubInterface> new_stub_factory;
    return wait_for_protocol_check(new_stub_factory(channel), kEthBackEndServiceApiVersion, "ETHBACKEND");
}

ProtocolVersionResult wait_for_mining_protocol_check(const std::unique_ptr<::txpool::Mining::StubInterface>& stub) {
    return wait_for_protocol_check(stub, kMiningServiceApiVersion, "MINING");
}

ProtocolVersionResult wait_for_mining_protocol_check(const std::shared_ptr<grpc::Channel>& channel) {
    NewStubFactory<::txpool::Mining::NewStub, ::txpool::Mining::StubInterface> new_stub_factory;
    return wait_for_protocol_check(new_stub_factory(channel), kMiningServiceApiVersion, "MINING");
}

ProtocolVersionResult wait_for_txpool_protocol_check(const std::unique_ptr<::txpool::Txpool::StubInterface>& stub) {
    return wait_for_protocol_check(stub, kTxPoolServiceApiVersion, "TXPOOL");
}

ProtocolVersionResult wait_for_txpool_protocol_check(const std::shared_ptr<grpc::Channel>& channel) {
    NewStubFactory<::txpool::Txpool::NewStub, ::txpool::Txpool::StubInterface> new_stub_factory;
    return wait_for_protocol_check(new_stub_factory(channel), kTxPoolServiceApiVersion, "TXPOOL");
}

}  // namespace silkworm::rpc
