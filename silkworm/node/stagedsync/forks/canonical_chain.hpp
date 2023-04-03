/*
   Copyright 2023 The Silkworm Authors

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
#include <concepts>
#include <set>
#include <variant>
#include <vector>

#include <silkworm/core/common/as_range.hpp>
#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/infra/common/asio_timer.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/node/stagedsync/execution_pipeline.hpp>
#include <silkworm/node/stagedsync/stages/stage.hpp>

namespace silkworm::stagedsync {

class CanonicalChain {
  public:
    explicit CanonicalChain(db::RWTxn&);

    BlockNum find_forking_point(db::RWTxn& tx, Hash header_hash);

    void update_up_to(BlockNum height, Hash header_hash);
    void delete_down_to(BlockNum unwind_point);

    BlockId initial_head();
    BlockId current_head();

    auto get_hash(BlockNum height) -> std::optional<Hash>;

  private:
    db::RWTxn& tx_;

    BlockId initial_head_{};
    BlockId current_head_{};

    static constexpr size_t kCacheSize = 1000;
    lru_cache<BlockNum, Hash> canonical_cache_;
};

}  // namespace silkworm::stagedsync
