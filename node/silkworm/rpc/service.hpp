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

#ifndef SILKWORM_RPC_SERVICE_HPP_
#define SILKWORM_RPC_SERVICE_HPP_

#include <cstddef>
#include <memory>
#include <unordered_set>

#include <silkworm/common/assert.hpp>

namespace silkworm::rpc {

constexpr std::size_t kRequestsInitialCapacity = 10000;

template <typename Rpc>
class RpcService {
  protected:
    RpcService(std::size_t requestsInitialCapacity) {
        requests_.reserve(requestsInitialCapacity);
    }

    RpcService() : RpcService(kRequestsInitialCapacity) {}

    [[maybe_unused]] auto add_request(Rpc* rpc) {
        SILKWORM_ASSERT(rpc != nullptr);
        return requests_.emplace(rpc);
    }

    [[maybe_unused]] auto remove_request(Rpc* rpc) {
        SILKWORM_ASSERT(rpc != nullptr);
        // Trick necessary because heterogeneous lookup for std::unordered_set requires C++20
        std::unique_ptr<Rpc> stale_rpc{rpc};
        auto removed_count = requests_.erase(stale_rpc);
        stale_rpc.release();
        return removed_count;
    }

    auto requests_bucket_count() const { return requests_.bucket_count(); }

    auto requests_size() const { return requests_.size(); }

  private:
    std::unordered_set<std::unique_ptr<Rpc>> requests_;
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_SERVICE_HPP_
