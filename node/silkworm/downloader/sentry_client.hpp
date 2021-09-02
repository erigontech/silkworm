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

#ifndef SILKWORM_SENTRY_CLIENT_HPP
#define SILKWORM_SENTRY_CLIENT_HPP

#include <interfaces/sentry.grpc.pb.h>

#include "internals/gRPCClient.hpp"
#include "internals/sentry_type_casts.hpp"

namespace silkworm {

/*
 * SentryClient is a client to the external Sentry
 * It connects to the Sentry, send rpc and receive reply.
 */

// An rpc
using SentryRpc = rpc::Call<sentry::Sentry>;

// The client
class SentryClient : public rpc::Client<sentry::Sentry> {
  public:
    using base_t = rpc::Client<sentry::Sentry>;

    explicit SentryClient(std::string sentry_addr);
    SentryClient(const SentryClient&) = delete;
    SentryClient(SentryClient&&) = delete;

    void exec_remotely(SentryRpc& rpc);

    // grpc::grpc_connectivity_state state() { return channel_->GetState(true); }

    void need_close() { closing_.store(true); }
    bool closing() { return closing_.load(); }

  protected:
    std::atomic<bool> closing_{false};
};


}
#endif  // SILKWORM_SENTRY_CLIENT_HPP
