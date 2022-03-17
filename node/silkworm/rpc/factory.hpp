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

#ifndef SILKWORM_RPC_FACTORY_HPP_
#define SILKWORM_RPC_FACTORY_HPP_

#include <cstddef>
#include <memory>
#include <unordered_set>

#include <grpcpp/grpcpp.h>
#include <gsl/pointers>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/log.hpp>

namespace silkworm::rpc {

//! Default initial capacity for the \ref Factory registry.
constexpr std::size_t kRequestsInitialCapacity = 10000;

//! Registry for the \ref Rpc typed requests currently alive.
/// Keeps track of RPC instances created by subclasses and automatically deletes them.
template <
    typename AsyncService,
    typename Request,
    typename Reply,
    template<typename, typename, typename> typename Rpc>
class Factory {
    using Call = Rpc<AsyncService, Request, Reply>;
    using CallHandlers = typename Call::Handlers;

  public:
    void create_rpc(AsyncService* service, grpc::ServerCompletionQueue* queue) {
        SILK_TRACE << "Factory::create_rpc START service: " << service << " queue: " << queue;

        auto rpc = new Call(service, queue, handlers_);
        add_rpc(rpc);

        SILK_TRACE << "Factory::create_rpc END rpc: " << rpc;
    }

    void cleanup_rpc(Call& rpc, bool cancelled) {
        SILK_TRACE << "Factory::cleanup_rpc START rpc: " << &rpc << " cancelled: " << cancelled;
        remove_rpc(&rpc);
        SILK_TRACE << "Factory::cleanup_rpc END rpc: " << &rpc;
    }

  protected:
    Factory(CallHandlers handlers, std::size_t requestsInitialCapacity) : handlers_(handlers) {
        requests_.reserve(requestsInitialCapacity);
    }

    Factory(CallHandlers handlers) : Factory(handlers, kRequestsInitialCapacity) {}

    Factory(
        typename CallHandlers::ProcessRequestFunc process_rpc,
        typename CallHandlers::RequestRpcFunc request_rpc,
        std::size_t requestsInitialCapacity) : handlers_{
            {
                [&](auto* svc, auto* cq) { create_rpc(svc, cq); },
                process_rpc,
                [&](auto& rpc, bool cancelled) { cleanup_rpc(rpc, cancelled); }
            },
            request_rpc
        } {
        requests_.reserve(requestsInitialCapacity);
    }

    Factory(
        typename CallHandlers::ProcessRequestFunc process_rpc,
        typename CallHandlers::RequestRpcFunc request_rpc)
        : Factory(process_rpc, request_rpc, kRequestsInitialCapacity) {}

    [[maybe_unused]] auto add_rpc(gsl::owner<Call*> rpc) {
        SILKWORM_ASSERT(rpc != nullptr);
        return requests_.emplace(rpc);
    }

    [[maybe_unused]] auto remove_rpc(gsl::owner<Call*> rpc) {
        SILKWORM_ASSERT(rpc != nullptr);
        // Trick necessary because heterogeneous lookup for std::unordered_set requires C++20
        std::unique_ptr<Call> stale_rpc{rpc};
        auto removed_count = requests_.erase(stale_rpc);
        stale_rpc.release();
        return removed_count;
    }

    auto requests_bucket_count() const { return requests_.bucket_count(); }

    auto requests_size() const { return requests_.size(); }

  private:
    CallHandlers handlers_;
    std::unordered_set<std::unique_ptr<Call>> requests_;
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_FACTORY_HPP_
