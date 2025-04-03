// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/db/stages.hpp>

namespace silkworm::rpc::stages {

inline const Bytes kHeaders = string_to_bytes(db::stages::kHeadersKey);
inline const Bytes kExecution = string_to_bytes(db::stages::kExecutionKey);
inline const Bytes kFinish = string_to_bytes(db::stages::kFinishKey);

Task<BlockNum> get_sync_stage_progress(db::kv::api::Transaction& tx, const Bytes& stage_key);

}  // namespace silkworm::rpc::stages
