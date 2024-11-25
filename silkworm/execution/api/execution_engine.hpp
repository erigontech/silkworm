/*
   Copyright 2024 The Silkworm Authors

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

#include <memory>
#include <optional>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/block_id.hpp>
#include <silkworm/core/types/hash.hpp>

#include "endpoint/validation.hpp"

namespace silkworm::execution::api {

struct ExecutionEngine {
    virtual ~ExecutionEngine() = default;

    virtual void open() = 0;
    virtual void close() = 0;

    // actions
    virtual void insert_blocks(const std::vector<std::shared_ptr<Block>>& blocks) = 0;
    virtual Task<VerificationResult> verify_chain(Hash head_block_hash) = 0;
    virtual bool notify_fork_choice_update(
        Hash head_block_hash,
        std::optional<Hash> finalized_block_hash,
        std::optional<Hash> safe_block_hash) = 0;

    // state
    virtual BlockNum block_progress() const = 0;
    virtual BlockId last_fork_choice() const = 0;
    virtual BlockId last_finalized_block() const = 0;
    virtual BlockId last_safe_block() const = 0;
    virtual BlockNum max_frozen_block_num() const = 0;

    // header/body retrieval
    virtual std::optional<BlockHeader> get_header(Hash) const = 0;
    virtual std::optional<BlockHeader> get_canonical_header(BlockNum) const = 0;
    virtual std::optional<Hash> get_canonical_hash(BlockNum) const = 0;
    virtual std::optional<BlockBody> get_body(Hash) const = 0;
    virtual std::optional<BlockBody> get_canonical_body(BlockNum) const = 0;
    virtual bool is_canonical(Hash) const = 0;
    virtual std::optional<BlockNum> get_block_num(Hash) const = 0;
    virtual std::vector<BlockHeader> get_last_headers(uint64_t limit) const = 0;
    virtual std::optional<TotalDifficulty> get_header_td(Hash, std::optional<BlockNum>) const = 0;
};

}  // namespace silkworm::execution::api
