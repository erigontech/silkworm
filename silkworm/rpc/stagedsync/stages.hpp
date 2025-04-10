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

inline const ByteView kHeaders = string_view_to_byte_view(db::stages::kHeadersKey);
inline const ByteView kExecution = string_view_to_byte_view(db::stages::kExecutionKey);
inline const ByteView kFinish = string_view_to_byte_view(db::stages::kFinishKey);

Task<BlockNum> get_sync_stage_progress(db::kv::api::Transaction& tx, ByteView stage_key);

}  // namespace silkworm::rpc::stages
