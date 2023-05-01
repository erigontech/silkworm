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

#include <boost/asio/awaitable.hpp>

#include <silkworm/infra/concurrency/active_component.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>
#include <silkworm/node/stagedsync/types.hpp>

namespace silkworm::execution {

namespace asio = boost::asio;
using namespace stagedsync;

class Server : public ActiveComponent {
  public:
    Server(NodeSettings&, db::RWAccess);

    auto open() -> asio::awaitable<void>;

    auto get_header(BlockNum block_number, Hash block_hash) -> asio::awaitable<std::optional<BlockHeader>>;

    auto get_body(BlockNum block_number, Hash block_hash) -> asio::awaitable<BlockBody>;

    auto is_canonical(Hash block_hash) -> asio::awaitable<bool>;

    auto get_block_num(Hash block_hash) -> asio::awaitable<BlockNum>;

    auto insert_headers(const BlockVector& blocks) -> asio::awaitable<void>;

    auto insert_bodies(const BlockVector& blocks) -> asio::awaitable<void>;

    auto validate_chain(Hash head_block_hash) -> asio::awaitable<execution::ValidationResult>;

    auto update_fork_choice(Hash head_block_hash, std::optional<Hash> finalized_block_hash = std::nullopt)
        -> asio::awaitable<ForkChoiceApplication>;

  private:
    void execution_loop() override;
    bool stop() override;
    static void handle_exception(std::exception_ptr e);

    ExecutionEngine exec_engine_;
    asio::io_context io_context_;
};

}  // namespace silkworm::execution
