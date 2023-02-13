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

#include "remote_client.hpp"

#include <silkworm/lightclient/rpc/protocol.hpp>
#include <silkworm/lightclient/sentinel/topic.hpp>
#include <silkworm/lightclient/snappy/snappy_codec.hpp>
#include <silkworm/node/common/log.hpp>
#include <silkworm/node/rpc/client/call.hpp>
#include <silkworm/sentry/common/timeout.hpp>  // TODO(canepat) refactor

namespace silkworm::cl::sentinel {

using namespace std::chrono;
using namespace boost::asio;

using LightClientBootstrapPtr = std::shared_ptr<eth::LightClientBootstrap>;

RemoteClient::RemoteClient(agrpc::GrpcContext& grpc_context, const std::shared_ptr<grpc::Channel>& channel)
    : grpc_context_(grpc_context), stub_(::sentinel::Sentinel::NewStub(channel)) {}

awaitable<void> RemoteClient::start() {
    sentry::common::Timeout timeout{1'000'000s};
    co_await timeout();
}

awaitable<LightClientBootstrapPtr> RemoteClient::bootstrap_request_v1(const eth::Root& root) {
    Bytes request_data = encode_and_write(root);
    ::sentinel::RequestData request;
    request.set_data(request_data.data(), request_data.size());
    request.set_topic(kLightClientBootstrapV1);
    ::sentinel::ResponseData response;
    const auto status = co_await rpc::unary_rpc(
        &::sentinel::Sentinel::Stub::AsyncSendRequest,stub_, request, response, grpc_context_);
    if (!status.ok()) {
        log::Warning() << "Bootstrap request V1 error: " << status.error_message();
        co_return LightClientBootstrapPtr{};
    }
    const std::vector<uint8_t> compressed_rsp{response.data().cbegin(), response.data().cend()};
    ByteView compressed_bootstrap{compressed_rsp.data(), compressed_rsp.size()};
    auto bootstrap = std::make_shared<eth::LightClientBootstrap>();
    const bool ok = decode_and_read(compressed_bootstrap, *bootstrap);
    co_return ok ? bootstrap : LightClientBootstrapPtr{};
}

}  // namespace silkworm::cl::sentinel
