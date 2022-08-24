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

#include <cstddef>
#include <memory>
#include <unordered_set>

#include <grpcpp/grpcpp.h>
#include <gsl/pointers>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/rpc/server/call.hpp>

namespace silkworm::rpc {

//! Default initial capacity for the \ref Factory registry.
constexpr std::size_t kRequestsInitialCapacity = 10000;

//! Registry for the \ref Call typed requests currently alive.
/// Keeps track of RPC instances created by subclasses and automatically deletes them.
template <typename AsyncService, typename Call>
class CallFactory {
    using CallHandlers = typename Call::Handlers;

  public:
    void create_rpc(boost::asio::io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue) {
        SILK_TRACE << "CallFactory::create_rpc START service: " << service << " queue: " << queue;

        auto rpc = new Call(scheduler, service, queue, handlers_);
        add_rpc(rpc);

        SILK_TRACE << "CallFactory::create_rpc END rpc: " << rpc;
    }

    void cleanup_rpc(BaseRpc& rpc, bool cancelled) {
        SILK_TRACE << "CallFactory::cleanup_rpc START rpc: " << &rpc << " cancelled: " << cancelled;
        remove_rpc(&rpc);
        SILK_TRACE << "CallFactory::cleanup_rpc END rpc: " << &rpc;
    }

  protected:
    CallFactory(CallHandlers handlers, std::size_t requestsInitialCapacity) : handlers_(handlers) {
        requests_.reserve(requestsInitialCapacity);
    }

    CallFactory(CallHandlers handlers) : CallFactory(handlers, kRequestsInitialCapacity) {}

    CallFactory(typename CallHandlers::RequestRpcFunc request_rpc, std::size_t requestsInitialCapacity)
        : handlers_{
              {[&](auto& scheduler, auto* svc, auto* cq) { create_rpc(scheduler, svc, cq); },
               [&](auto& rpc, bool cancelled) { cleanup_rpc(rpc, cancelled); }},
              request_rpc} {
        requests_.reserve(requestsInitialCapacity);
    }

    CallFactory(typename CallHandlers::RequestRpcFunc request_rpc)
        : CallFactory(request_rpc, kRequestsInitialCapacity) {}

    [[maybe_unused]] auto add_rpc(gsl::owner<BaseRpc*> rpc) {
        SILKWORM_ASSERT(rpc != nullptr);
        return requests_.emplace(rpc);
    }

    [[maybe_unused]] auto remove_rpc(gsl::owner<BaseRpc*> rpc) {
        SILKWORM_ASSERT(rpc != nullptr);
        // Trick necessary because heterogeneous lookup for std::unordered_set requires C++20
        std::unique_ptr<BaseRpc> stale_rpc{rpc};
        auto removed_count = requests_.erase(stale_rpc);
        stale_rpc.release();
        return removed_count;
    }

    auto requests_bucket_count() const { return requests_.bucket_count(); }

    auto requests_size() const { return requests_.size(); }

  private:
    CallHandlers handlers_;
    std::unordered_set<std::unique_ptr<BaseRpc>> requests_;
};

}  // namespace silkworm::rpc
