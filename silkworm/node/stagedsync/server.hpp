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

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>

#include <silkworm/infra/concurrency/active_component.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>
#include <silkworm/node/stagedsync/types.hpp>

namespace silkworm::execution {

namespace asio = boost::asio;
using namespace stagedsync;

//! A server for 'execution' gRPC interface.
class Server : public ActiveComponent {
  public:
    Server(NodeSettings&, db::RWAccess);

    // actions
    Task<void> insert_headers(const BlockVector& blocks);  // [[thorax-compliant]]
    Task<void> insert_bodies(const BlockVector& blocks);   // [[thorax-compliant]]
    Task<void> insert_blocks(const BlockVector& blocks);

    Task<execution::ValidationResult> validate_chain(Hash head_block_hash);  // [[thorax-compliant]]

    Task<ForkChoiceApplication> update_fork_choice(Hash head_block_hash, std::optional<Hash> finalized_block_hash = std::nullopt);  // [[thorax-compliant]]

    // state
    Task<BlockNum> block_progress();
    Task<BlockId> last_fork_choice();

    // header/body retrieval
    Task<std::optional<BlockHeader>> get_header(Hash block_hash);             // [[thorax-compliant]]
    Task<std::optional<BlockHeader>> get_header(BlockNum height, Hash hash);  // [[thorax-compliant]]
    Task<std::optional<BlockBody>> get_body(Hash block_hash);                 // [[thorax-compliant]]
    Task<std::optional<BlockBody>> get_body(BlockNum block_number);           // [[thorax-compliant]]

    Task<bool> is_canonical(Hash block_hash);                      // [[thorax-compliant]]
    Task<std::optional<BlockNum>> get_block_num(Hash block_hash);  // [[thorax-compliant]]

    Task<std::vector<BlockHeader>> get_last_headers(BlockNum limit);
    Task<std::optional<TotalDifficulty>> get_header_td(Hash, std::optional<BlockNum>);  // to remove

    asio::io_context& get_executor() { return io_context_; }

  private:
    void execution_loop() override;
    bool stop() override;
    static void handle_exception(const std::exception_ptr& e);

    ExecutionEngine exec_engine_;
    asio::io_context io_context_;
};

}  // namespace silkworm::execution
