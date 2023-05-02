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

#include <silkworm/node/stagedsync/server.hpp>

#include "client.hpp"

namespace silkworm::execution {

class LocalClient : public Client {
  public:
    explicit LocalClient(Server& local_server);

    // actions
    ERIGON_API auto insert_headers(const BlockVector& blocks) -> awaitable<void> override;
    ERIGON_API auto insert_bodies(const BlockVector& blocks) -> awaitable<void> override;
    auto insert_blocks(const BlockVector& blocks) -> awaitable<void> override;

    ERIGON_API auto validate_chain(Hash head_block_hash) -> awaitable<ValidationResult> override;

    ERIGON_API auto update_fork_choice(Hash head_block_hash,
                                       std::optional<Hash> finalized_block_hash = std::nullopt) -> awaitable<ForkChoiceApplication> override;

    // state
    auto get_block_progress() -> awaitable<BlockNum> override;

    // header/body retrieval
    ERIGON_API auto get_header(BlockNum block_number, Hash block_hash) -> awaitable<std::optional<BlockHeader>> override;
    ERIGON_API auto get_body(BlockNum block_number, Hash block_hash) -> awaitable<BlockBody> override;

    ERIGON_API auto is_canonical(Hash block_hash) -> awaitable<bool> override;
    ERIGON_API auto get_block_num(Hash block_hash) -> awaitable<BlockNum> override;

    auto get_last_headers(BlockNum limit) const -> std::vector<BlockHeader> override;

    asio::io_context& get_executor() { return local_server_.get_executor(); }

  private:
    Server& local_server_;
};

}  // namespace silkworm::execution
