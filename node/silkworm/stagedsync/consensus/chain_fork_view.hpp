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
#include <silkworm/types/block.hpp>
#include <silkworm/stagedsync/execution_engine.hpp>
#include <silkworm/downloader/internals/types.hpp>

namespace silkworm::stagedsync::consensus {

class ChainForkView {
  public:
    ChainForkView(ExecutionEngine&);

    void add(const BlockHeader& header);

    BlockNum head_height() const;
    Hash head_hash() const;
    BigInt head_total_difficulty() const;

    bool head_changed() const;

    BlockIdPair unwind_point() const;
    bool unwind_needed() const;

  private:
    static constexpr size_t kCanonicalCacheSize = 1000;

    BlockIdPair find_forking_point(const BlockHeader& header, BlockNum height, const Hash& parent_hash);

    ExecutionEngine& exec_engine_;
    lru_cache<BlockNum, Hash> canonical_cache_;

    BlockIdPair initial_head_{};
    BlockIdPair current_head_{};
    BigInt initial_head_td_, current_head_td_; // td of initial and current head
    std::optional<BlockIdPair> unwind_point_; // point to unwind to
    Hash previous_hash_;
};

}