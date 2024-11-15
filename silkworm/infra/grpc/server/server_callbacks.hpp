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

#include <mutex>

#include <grpcpp/grpcpp.h>

#include <silkworm/infra/common/log.hpp>

namespace silkworm::rpc {

class ServerGlobalCallbacks {
  public:
    ServerGlobalCallbacks() {
        // NOTE: Despite its documentation, SetGlobalCallbacks() does take the ownership
        // of the object pointer. So we just "new" and let underlying GRPC manage its lifetime.
        static std::once_flag callback_init_flag;
        std::call_once(callback_init_flag, []() {
            grpc::Server::SetGlobalCallbacks(new Callbacks());
        });
    }

  private:
    class Callbacks final : public grpc::Server::GlobalCallbacks {
      public:
        Callbacks() = default;
        ~Callbacks() override = default;

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
    };
};

}  // namespace silkworm::rpc
