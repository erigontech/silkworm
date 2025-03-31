// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
