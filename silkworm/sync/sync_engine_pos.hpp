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

#include <silkworm/node/common/log.hpp>
#include <silkworm/node/common/settings.hpp>
#include <silkworm/node/concurrency/active_component.hpp>
#include <silkworm/sync/engine_apis/structs.hpp>
#include <silkworm/sync/internals/chain_fork_view.hpp>
#include <silkworm/sync/messages/internal_message.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>

#include "block_exchange.hpp"

namespace silkworm::chainsync::pos {

class PoSSync : public ActiveComponent {
  public:
    PoSSync(BlockExchange&, stagedsync::ExecutionEngine&);

    void execution_loop() final; /*[[long_running]]*/

    // public interface called by the external PoS client
    PayloadStatus new_payload(const ExecutionPayload&, seconds_t timeout = 8s);
    PayloadStatus fork_choice_update(const ForkChoiceState&, const std::optional<PayloadAttributes>&, seconds_t timeout = 8s);
    ExecutionPayload get_payload(std::string payloadId, seconds_t timeout = 1s);
    TransitionConfiguration exchange_transition_config(const TransitionConfiguration&, seconds_t timeout = 1s);

  private:
    static constexpr BlockNum TRANSITION_BLOCK = 15537394;  // todo: get from chain config
    Block make_execution_block(const ExecutionPayload& payload);
    void validate_execution_block(evmc::bytes32 blockHash, const Block& block);
    bool extends_canonical(const Block& block, Hash block_hash);

    BlockExchange& block_exchange_;
    stagedsync::ExecutionEngine& exec_engine_;
    ChainForkView chain_fork_view_;
};

}  // namespace silkworm::chainsync::pos
