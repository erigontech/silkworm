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

#include "client.hpp"

namespace silkworm::execution {

namespace asio = boost::asio;
class Server;

//! A client of 'execution' gRPC interface running in-process together with server.
class LocalClient : public Client {
  public:
    explicit LocalClient(Server& local_server);

    asio::io_context& get_executor() override;

    // actions
    auto insert_headers(const BlockVector& blocks) -> asio::awaitable<void> override;
    auto insert_bodies(const BlockVector& blocks) -> asio::awaitable<void> override;
    auto insert_blocks(const BlockVector& blocks) -> asio::awaitable<void> override;

    auto validate_chain(Hash head_block_hash) -> asio::awaitable<ValidationResult> override;

    auto update_fork_choice(Hash head_block_hash, std::optional<Hash> finalized_block_hash)
        -> asio::awaitable<ForkChoiceApplication> override;

    // state
    auto block_progress() -> asio::awaitable<BlockNum> override;
    auto last_fork_choice() -> asio::awaitable<BlockId> override;

    // header/body retrieval
    auto get_header(Hash block_hash) -> asio::awaitable<std::optional<BlockHeader>> override;
    auto get_header(BlockNum height, Hash hash) -> asio::awaitable<std::optional<BlockHeader>> override;
    auto get_body(Hash block_hash) -> asio::awaitable<std::optional<BlockBody>> override;
    auto get_body(BlockNum block_number) -> asio::awaitable<std::optional<BlockBody>> override;

    auto is_canonical(Hash block_hash) -> asio::awaitable<bool> override;
    auto get_block_num(Hash block_hash) -> asio::awaitable<std::optional<BlockNum>> override;

    auto get_last_headers(BlockNum limit) -> asio::awaitable<std::vector<BlockHeader>> override;
    auto get_header_td(Hash, std::optional<BlockNum>) -> asio::awaitable<std::optional<TotalDifficulty>> override;

  private:
    Server& local_server_;
};

}  // namespace silkworm::execution
