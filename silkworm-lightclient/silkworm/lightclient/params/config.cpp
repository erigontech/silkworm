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

#include "config.hpp"

#include <random>

#include "silkworm/common/assert.hpp"

namespace silkworm::cl {

std::optional<std::string> get_checkpoint_sync_endpoint(uint64_t chain_id) noexcept {
    const auto endpoint_it = kCheckpointSyncEndpoints.find(chain_id);
    if (endpoint_it == kCheckpointSyncEndpoints.end()) {
        return std::nullopt;
    }
    const auto endpoints = endpoint_it->second;

    // Randomly select one checkpoint sync endpoint for the chain
    static std::random_device random_dev;
    static std::mt19937 random_gen(random_dev());
    static std::uniform_int_distribution<std::size_t> distribution{0, endpoints.size()};
    const std::size_t random_index = distribution(random_gen);
    SILKWORM_ASSERT(random_index < endpoints.size());

    return endpoints.at(random_index);
}

}  // namespace silkworm::cl
