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
    Task<void> insert_headers(const BlockVector& blocks) override;
    Task<void> insert_bodies(const BlockVector& blocks) override;
    Task<void> insert_blocks(const BlockVector& blocks) override;

    Task<ValidationResult> validate_chain(Hash head_block_hash) override;

    Task<ForkChoiceApplication> update_fork_choice(Hash head_block_hash, std::optional<Hash> finalized_block_hash) override;

    // state
    Task<BlockNum> block_progress() override;
    Task<BlockId> last_fork_choice() override;

    // header/body retrieval
    Task<std::optional<BlockHeader>> get_header(Hash block_hash) override;
    Task<std::optional<BlockHeader>> get_header(BlockNum height, Hash hash) override;
    Task<std::optional<BlockBody>> get_body(Hash block_hash) override;
    Task<std::optional<BlockBody>> get_body(BlockNum block_number) override;

    Task<bool> is_canonical(Hash block_hash) override;
    Task<std::optional<BlockNum>> get_block_num(Hash block_hash) override;

    Task<std::vector<BlockHeader>> get_last_headers(BlockNum limit) override;
    Task<std::optional<TotalDifficulty>> get_header_td(Hash, std::optional<BlockNum>) override;

  private:
    Server& local_server_;
};

}  // namespace silkworm::execution
