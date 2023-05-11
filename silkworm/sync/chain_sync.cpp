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

#include "chain_sync.hpp"

namespace silkworm::chainsync {

ChainSync::ChainSync(BlockExchange& block_exchange, execution::Client& exec_engine)
    : block_exchange_{block_exchange},
      exec_engine_{exec_engine},
      chain_fork_view_{ChainHead{}} {  // we cannot call exec_engine.get_canonical_head() at this point because EE is not started
}

}  // namespace silkworm::chainsync
