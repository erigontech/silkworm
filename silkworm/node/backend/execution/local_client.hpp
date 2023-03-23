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

#include <silkworm/node/backend/execution/client.hpp>
#include <silkworm/node/backend/execution/server.hpp>

namespace silkworm::execution {

class LocalClient : public Client {
  public:
    explicit LocalClient(Server* local_server);

    auto start() -> awaitable<void> override;

    auto get_header(BlockNum block_number, Hash block_hash) -> awaitable<BlockHeader> override;

    auto get_body(BlockNum block_number, Hash block_hash) -> awaitable<BlockBody> override;

    auto is_canonical(Hash block_hash) -> awaitable<bool> override;

    auto get_block_num(Hash block_hash) -> awaitable<BlockNum> override;

    auto insert_headers(const BlockVector& blocks) -> awaitable<void> override;

    auto insert_bodies(const BlockVector& blocks) -> awaitable<void> override;

    auto verify_chain(Hash head_block_hash) -> awaitable<stagedsync::ExecutionEngine::VerificationResult> override;

    auto notify_fork_choice_update(Hash head_block_hash, std::optional<Hash> finalized_block_hash = std::nullopt) -> awaitable<bool> override;

  private:
    Server* local_server_;
};

}  // namespace silkworm::execution
