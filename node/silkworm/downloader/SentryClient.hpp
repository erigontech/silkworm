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
#ifndef SILKWORM_SENTRYCLIENT_HPP
#define SILKWORM_SENTRYCLIENT_HPP

#include <interfaces/sentry.grpc.pb.h>
#include "TypesForGrpc.hpp"
#include "gRPCAsyncClient.hpp"
#include "ActiveComponent.hpp"

namespace silkworm {

/*
 * SentryClient is a client to the external Sentry
 * It connects to the Sentry, send rpc and receive reply.
 */

// An rpc
using SentryRpc = rpc::AsyncCall<sentry::Sentry>;

// The client
class SentryClient : public rpc::AsyncClient<sentry::Sentry> {
  public:
    using base_t = rpc::AsyncClient<sentry::Sentry>;

    explicit SentryClient(std::string sentry_addr);

    void exec_remotely(std::shared_ptr<SentryRpc> rpc);

    std::shared_ptr<SentryRpc> receive_one_reply();  // wait for a single rpc reply, to call repeatedly

    // grpc::grpc_connectivity_state state() { return channel_->GetState(true); }
};

// A SentryClient with an infinite loop to receive rpc forever
class ActiveSentryClient : public SentryClient, public ActiveComponent {
  public:
    using SentryClient::SentryClient;   // use parent constructor

    virtual void execution_loop();
};

}
#endif  // SILKWORM_SENTRYCLIENT_HPP
