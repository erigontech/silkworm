// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>

#include <silkworm/infra/concurrency/task.hpp>

#include "kvdb/mdbx.hpp"

namespace silkworm::datastore {

struct StageScheduler {
    virtual ~StageScheduler() = default;

    //! Schedule a callback to run inside the stage loop.
    virtual Task<void> schedule(std::function<void(datastore::kvdb::RWTxn&)> callback) = 0;
};

}  // namespace silkworm::datastore
