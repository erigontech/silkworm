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

#include <atomic>
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

    static bool check_and_clear_bad_port_error() {
        return bad_port_error.exchange(false);
    }

  private:
    static inline std::atomic<bool> bad_port_error{false};
    class Callbacks final : public grpc::Server::GlobalCallbacks {
      public:
        Callbacks() = default;
        ~Callbacks() override = default;

        void PreSynchronousRequest(grpc::ServerContext*) override{};
        void PostSynchronousRequest(grpc::ServerContext*) override{};

        void AddPort(grpc::Server*, const std::string&,
                     grpc::ServerCredentials*, int port) override {
            if (port == 0) {
                ServerGlobalCallbacks::bad_port_error.store(true, std::memory_order_release);
            }
        }
    };
};

}  // namespace silkworm::rpc
