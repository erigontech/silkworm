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

#include <memory>

#include <silkworm/node/execution/api/client.hpp>
#include <silkworm/sync/block_exchange.hpp>
#include <silkworm/sync/internals/chain_fork_view.hpp>

namespace silkworm::chainsync {

class ChainSync {
  public:
    ChainSync(BlockExchange&, execution::api::Client&);
    virtual ~ChainSync() = default;

    ChainSync(const ChainSync&) = delete;
    ChainSync& operator=(const ChainSync&) = delete;

    virtual Task<void> async_run() = 0;

  protected:
    BlockExchange& block_exchange_;
    std::shared_ptr<execution::api::Service> exec_engine_;
    ChainForkView chain_fork_view_;
};

}  // namespace silkworm::chainsync
