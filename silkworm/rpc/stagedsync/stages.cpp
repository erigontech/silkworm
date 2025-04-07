// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "stages.hpp"

#include <stdexcept>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/db/tables.hpp>

namespace silkworm::rpc::stages {

Task<BlockNum> get_sync_stage_progress(db::kv::api::Transaction& tx, const Bytes& stage_key) {
    const auto kv_pair = co_await tx.get(db::table::kSyncStageProgressName, stage_key);
    const auto value = kv_pair.value;
    if (value.empty()) {
        co_return 0;
    }
    if (value.size() < 8) {
        throw std::runtime_error("data too short, expected 8 got " + std::to_string(value.size()));
    }
    BlockNum block_num = endian::load_big_u64(value.substr(0, 8).data());
    co_return block_num;
}

}  // namespace silkworm::rpc::stages
