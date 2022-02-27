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

#include "parallel_bloomer.hpp"

#include <silkworm/common/util.hpp>

namespace silkworm {

Bloom ParallelBloomer::bloom_filter(const std::vector<Log>& logs) {
    Bloom bloom;
    for (const Log& log : logs) {
        thread_pool_.push_task([&]() {
            const ethash::hash256 hash{keccak256(log.address)};
            std::lock_guard guard{mutex_};
            bloom.m3_2048(hash.bytes);
        });
        for (const auto& topic : log.topics) {
            thread_pool_.push_task([&]() {
                const ethash::hash256 hash{keccak256(topic)};
                std::lock_guard guard{mutex_};
                bloom.m3_2048(hash.bytes);
            });
        }
    }
    thread_pool_.wait_for_tasks();
    return bloom;
}

}  // namespace silkworm
