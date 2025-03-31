// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/db/kv/api/transaction.hpp>

namespace silkworm::rpc::ethdb {

using Walker = std::function<bool(Bytes&, Bytes&)>;

Task<void> walk(db::kv::api::Transaction& tx, const std::string& table, ByteView start_key, uint32_t fixed_bits, Walker w);

Task<void> for_prefix(db::kv::api::Transaction& tx, const std::string& table, ByteView prefix, Walker w);

}  // namespace silkworm::rpc::ethdb
