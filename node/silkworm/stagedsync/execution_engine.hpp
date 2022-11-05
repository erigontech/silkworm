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

#include <atomic>
#include <map>
#include <vector>

#include <silkworm/common/asio_timer.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/downloader/internals/types.hpp>
#include <silkworm/stagedsync/stage.hpp>

namespace silkworm::stagedsync {

class ExecutionEngine {
  public:
    explicit ExecutionEngine(silkworm::NodeSettings*, mdbx::env*);
    ~ExecutionEngine() = default;

    void insert_headers(const std::vector<BlockHeader>&);
    void insert_bodies(const std::vector<BlockBody>&));

    bool verify_chain_(Hash header_hash);

    bool update_fork_choice(Hash header_hash);

    auto get_headers(Hash header_hash);
    auto get_bodies(Hash header_hash);
};
}  // namespace silkworm::stagedsync
