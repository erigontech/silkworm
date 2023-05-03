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

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/active_component.hpp>
#include <silkworm/node/common/settings.hpp>
#include <silkworm/node/stagedsync/client.hpp>
#include <silkworm/sync/engine_apis/structs.hpp>
#include <silkworm/sync/internals/chain_fork_view.hpp>
#include <silkworm/sync/messages/internal_message.hpp>

#include "block_exchange.hpp"

namespace silkworm::chainsync {

namespace asio = boost::asio;

class PoSSync {
  public:
    PoSSync(BlockExchange&, execution::Client&);

    auto execution_loop() -> asio::awaitable<void>; /*[[long_running]]*/

    // public interface called by the external PoS client
    auto new_payload(const ExecutionPayload&) -> asio::awaitable<PayloadStatus>;
    auto fork_choice_update(const ForkChoiceState&, const std::optional<PayloadAttributes>&) -> asio::awaitable<ForkChoiceUpdateReply>;
    auto get_payload(std::string payloadId) -> asio::awaitable<ExecutionPayload>;
    auto exchange_transition_config(const TransitionConfiguration&) -> asio::awaitable<TransitionConfiguration>;

  private:
    auto make_execution_block(const ExecutionPayload& payload) -> std::shared_ptr<Block>;
    void do_sanity_checks(const BlockHeader& header, TotalDifficulty parent_td);
    bool extends_canonical(const Block& block, Hash block_hash);
    auto has_bad_ancestor(const Hash& block_hash) -> std::tuple<bool, Hash>;

    BlockExchange& block_exchange_;
    execution::Client& exec_engine_;
    ChainForkView chain_fork_view_;
};

}  // namespace silkworm::chainsync
