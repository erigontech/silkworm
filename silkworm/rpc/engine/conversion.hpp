// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/execution/api/endpoint/checkers.hpp>
#include <silkworm/execution/api/endpoint/range.hpp>
#include <silkworm/rpc/types/execution_payload.hpp>

namespace silkworm::rpc::engine {

rpc::ForkChoiceUpdatedReply fork_choice_updated_reply_from_result(const execution::api::ForkChoiceResult&);

rpc::ExecutionPayloadBodies execution_payloads_from_bodies(const execution::api::BlockBodies&);

//! Convert an ExecutionPayload to a Block as per Engine API spec
std::shared_ptr<Block> block_from_execution_payload(const rpc::ExecutionPayload&);

}  // namespace silkworm::rpc::engine
