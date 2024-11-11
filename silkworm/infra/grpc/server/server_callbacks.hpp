/*
   Copyright 2024 The Silkworm Authors

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

#pragma once

#include <grpcpp/grpcpp.h>

#include <silkworm/infra/common/log.hpp>

namespace silkworm::rpc {

class ServerGlobalCallbacks : public grpc::Server::GlobalCallbacks {
  public:
    static ServerGlobalCallbacks* create() {
        static ServerGlobalCallbacks instance;
        return &instance;
    }

    ~ServerGlobalCallbacks() override = default;

    void PreSynchronousRequest([[maybe_unused]] grpc::ServerContext* context) override{};
    void PostSynchronousRequest([[maybe_unused]] grpc::ServerContext* context) override{};

    void AddPort([[maybe_unused]] grpc::Server* server, const std::string& addr,
                 [[maybe_unused]] grpc::ServerCredentials* creds, int port) override {
        if (port != 0) {
            SILK_TRACE << "Successfully bound server to address: " << addr << " on port: " << port;
        } else {
            SILK_ERROR << "Failed to bind server to address " << addr
                       << ". Port is already in use.";
        }
    }

  protected:
    ServerGlobalCallbacks() = default;
};

void set_global_callbacks();

}  // namespace silkworm::rpc
