// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include "endpoint/state_change.hpp"
#include "endpoint/temporal_point.hpp"
#include "endpoint/temporal_range.hpp"
#include "endpoint/version.hpp"
#include "transaction.hpp"

namespace silkworm::db::kv::api {

struct Service {
    virtual ~Service() = default;

    // rpc Version(google.protobuf.Empty) returns (types.VersionReply);
    virtual Task<Version> version() = 0;

    // rpc Tx(stream Cursor) returns (stream Pair);
    virtual Task<std::unique_ptr<Transaction>> begin_transaction() = 0;

    // rpc StateChanges(StateChangeRequest) returns (stream StateChangeBatch);
    virtual Task<void> state_changes(const StateChangeOptions& options, StateChangeConsumer consumer) = 0;
};

}  // namespace silkworm::db::kv::api
