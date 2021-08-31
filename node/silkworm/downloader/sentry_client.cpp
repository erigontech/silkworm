/*
   Copyright 2021 The Silkworm Authors

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

#include <silkworm/common/log.hpp>

#include "sentry_client.hpp"

namespace silkworm {

SentryClient::SentryClient(std::string sentry_addr)
    : base_t(grpc::CreateChannel(sentry_addr, grpc::InsecureChannelCredentials())) {}

void SentryClient::exec_remotely(std::shared_ptr<SentryRpc> rpc) { base_t::exec_remotely(rpc); }

std::shared_ptr<SentryRpc> SentryClient::receive_one_reply() {
    // check the gRPC queue, and trigger gRPC processing (gRPC will create a message)
    auto executed_rpc = base_t::receive_one_result();

    // log gRPC termination
    if (executed_rpc && executed_rpc->terminated()) {
        auto status = executed_rpc->status();
        if (status.ok()) {
            SILKWORM_LOG(LogLevel::Trace) << "RPC ok, " << executed_rpc->name() << "\n";
        } else {
            SILKWORM_LOG(LogLevel::Warn) << "RPC failed, " << executed_rpc->name() << ", error: '"
                                         << status.error_message() << "', code: " << status.error_code()
                                         << ", details: " << status.error_details() << std::endl;
        }
    }

    return executed_rpc;
}

void ActiveSentryClient::execution_loop() {
    try {
        while (!stopping_) {
            receive_one_reply();
        }
    } catch (const std::exception& e) {
        SILKWORM_LOG(LogLevel::Critical) << "SentryClient execution_loop exiting due to exception: " << e.what()
                                         << "\n";
        throw e;
    }

    SILKWORM_LOG(LogLevel::Info) << "SentryClient execution_loop exiting...\n";
}

}  // namespace silkworm
