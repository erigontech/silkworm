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

#include <silkworm/core/types/block.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>
#include <silkworm/node/stagedsync/types.hpp>

namespace silkworm::execution {

using boost::asio::awaitable;

class Client {
  public:
    virtual ~Client() = default;

    virtual auto start() -> awaitable<void> = 0;

    virtual auto get_header(BlockNum block_number, Hash block_hash) -> awaitable<BlockHeader> = 0;

    virtual auto get_body(BlockNum block_number, Hash block_hash) -> awaitable<BlockBody> = 0;

    virtual auto is_canonical(Hash block_hash) -> awaitable<bool> = 0;

    virtual auto get_block_num(Hash block_hash) -> awaitable<BlockNum> = 0;

    virtual auto insert_headers(const BlockVector& blocks) -> awaitable<void> = 0;

    virtual auto insert_bodies(const BlockVector& blocks) -> awaitable<void> = 0;

    virtual auto validate_chain(Hash head_block_hash) -> awaitable<ValidationResult> = 0;

    virtual auto update_fork_choice(Hash head_block_hash,
                                    std::optional<Hash> finalized_block_hash = std::nullopt) -> awaitable<ForkChoiceApplication> = 0;
};

}  // namespace silkworm::execution
