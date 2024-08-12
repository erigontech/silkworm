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

#pragma once

#include <grpcpp/grpcpp.h>

namespace silkworm::rpc {

/**
 * Port in use global callback, called through static grpc::Server::SetGlobalCallbacks.
 * an instance of `Inuseportglobalcallbacks` need to be instantiated, and it's lifetime
 * should last as the lifetime of the `Server`, if there are multiple calls to the `Server`
 *,it should remain life, and call the instance just once.
 * use call_once form std to call set_global_callbacks below to call the instance just once
 * as follows:
 * std::call_once(once_flag, silkworm::rpc::set_global_callbacks, inuseport_callback);
 */
class InusePortGlobalCallbacks : public grpc::Server::GlobalCallbacks {
public:
    virtual void PreSynchronousRequest(grpc::ServerContext*) override {}

    virtual void PostSynchronousRequest(grpc::ServerContext*) override {}

    virtual void AddPort(grpc::Server *server, const std::string &addr, grpc::ServerCredentials*, int port) override {
        // if the port is unassigned, or zero, then port is in use.
        if (!port) {
            std::cout << "server " << server << " port at addr: " << addr << " is already in use " << std::endl;
        }
    }
};

void set_global_callbacks(InusePortGlobalCallbacks *inuseport_callback) {
        grpc::Server::SetGlobalCallbacks(inuseport_callback);
}
}  // namespace silkworm::rpc
