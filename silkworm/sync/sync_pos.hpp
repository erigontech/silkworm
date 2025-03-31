// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/active_component.hpp>
#include <silkworm/rpc/engine/execution_engine.hpp>
#include <silkworm/rpc/types/execution_payload.hpp>
#include <silkworm/sync/internals/chain_fork_view.hpp>
#include <silkworm/sync/messages/internal_message.hpp>

#include "block_exchange.hpp"
#include "chain_sync.hpp"

namespace silkworm::chainsync {

class PoSSync : public ChainSync, public rpc::engine::ExecutionEngine {
  public:
    PoSSync(IBlockExchange&, execution::api::Client&);

    Task<void> async_run() override;

    // public interface to download blocks
    Task<void> download_blocks(); /*[[long_running]]*/

    // public interface called by the external PoS client
    Task<rpc::PayloadStatus> new_payload(const rpc::NewPayloadRequest& request, std::chrono::milliseconds timeout) override;
    Task<rpc::ForkChoiceUpdatedReply> fork_choice_updated(const rpc::ForkChoiceUpdatedRequest& request, std::chrono::milliseconds timeout) override;
    Task<rpc::ExecutionPayloadAndValue> get_payload(uint64_t payload_id, std::chrono::milliseconds timeout) override;
    Task<rpc::ExecutionPayloadBodies> get_payload_bodies_by_hash(const std::vector<Hash>& block_hashes, std::chrono::milliseconds timeout) override;
    Task<rpc::ExecutionPayloadBodies> get_payload_bodies_by_range(BlockNum start, uint64_t count, std::chrono::milliseconds timeout) override;

  private:
    void do_sanity_checks(const BlockHeader& header, TotalDifficulty parent_td);
    std::tuple<bool, Hash> has_valid_ancestor(const Hash& block_hash);

    size_t active_chain_validations_{0};
};

}  // namespace silkworm::chainsync
