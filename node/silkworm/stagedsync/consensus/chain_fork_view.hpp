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

#include <silkworm/common/lru_cache.hpp>
#include <silkworm/downloader/internals/types.hpp>
#include <silkworm/stagedsync/execution_engine.hpp>
#include <silkworm/types/block.hpp>

namespace silkworm::stagedsync::consensus {

class ChainForkView {
  public:
    ChainForkView(ExecutionEngine&);

    void add(const BlockHeader& header);

    BlockNum head_height() const;
    Hash head_hash() const;
    BigInt head_total_difficulty() const;

    bool head_changed() const;

  private:
    ExecutionEngine& exec_engine_;

    BlockIdPair initial_head_{};
    BlockIdPair current_head_{};
    BigInt initial_head_td_, current_head_td_;  // td of initial and current head
    Hash previous_hash_;
};

}  // namespace silkworm::stagedsync::consensus