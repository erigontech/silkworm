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

#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/block_id.hpp>
#include <silkworm/node/stagedsync/types.hpp>

namespace silkworm::execution {

namespace asio = boost::asio;

class Client {
  public:
    virtual ~Client() = default;

    virtual asio::io_context& get_executor() = 0;

    // actions
    virtual Task<void> insert_headers(const BlockVector& blocks) = 0;
    virtual Task<void> insert_bodies(const BlockVector& blocks) = 0;
    virtual Task<void> insert_blocks(const BlockVector& blocks) = 0;

    virtual Task<ValidationResult> validate_chain(Hash head_block_hash) = 0;

    virtual Task<ForkChoiceApplication> update_fork_choice(Hash head_block_hash, std::optional<Hash> finalized_block_hash) = 0;

    // state
    virtual Task<BlockNum> block_progress() = 0;
    virtual Task<BlockId> last_fork_choice() = 0;

    // header/body retrieval
    virtual Task<std::optional<BlockHeader>> get_header(Hash block_hash) = 0;
    virtual Task<std::optional<BlockHeader>> get_header(BlockNum height, Hash hash) = 0;
    virtual Task<std::optional<BlockBody>> get_body(Hash block_hash) = 0;
    virtual Task<std::optional<BlockBody>> get_body(BlockNum block_number) = 0;

    virtual Task<bool> is_canonical(Hash block_hash) = 0;
    virtual Task<std::optional<BlockNum>> get_block_num(Hash block_hash) = 0;

    virtual Task<std::vector<BlockHeader>> get_last_headers(BlockNum limit) = 0;
    virtual Task<std::optional<TotalDifficulty>> get_header_td(Hash, std::optional<BlockNum>) = 0;
};

}  // namespace silkworm::execution
