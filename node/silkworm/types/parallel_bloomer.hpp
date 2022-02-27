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

#ifndef SILKWORM_TYPES_PARALLEL_BLOOMER_HPP_
#define SILKWORM_TYPES_PARALLEL_BLOOMER_HPP_

#include <mutex>

#include <silkworm/concurrency/thread_pool.hpp>
#include <silkworm/types/bloom.hpp>

namespace silkworm {

class ParallelBloomer : public LogsBloomer {
  public:
    // Not copyable nor movable
    ParallelBloomer(const ParallelBloomer&) = delete;
    ParallelBloomer& operator=(const ParallelBloomer&) = delete;

    ParallelBloomer() = default;

    Bloom bloom_filter(const std::vector<Log>& logs) override;

  private:
    thread_pool thread_pool_{std::thread::hardware_concurrency()};
    std::mutex mutex_;
};

}  // namespace silkworm

#endif  // SILKWORM_TYPES_PARALLEL_BLOOMER_HPP_
