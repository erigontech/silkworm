// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <memory>
#include <optional>

#include <silkworm/infra/concurrency/task.hpp>

#include <gmock/gmock.h>

#include <silkworm/core/common/util.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/ethdb/transaction.hpp>

namespace silkworm::rpc::test {

class MockStateView : public ethdb::kv::StateView {
  public:
    MOCK_METHOD((Task<std::optional<silkworm::Bytes>>), get, (const silkworm::Bytes&));
    MOCK_METHOD((Task<std::optional<silkworm::Bytes>>), get_code, (const silkworm::Bytes&));
};

class MockStateCache : public ethdb::kv::StateCache {
  public:
    MOCK_METHOD((std::unique_ptr<ethdb::kv::StateView>), get_view, (ethdb::Transaction&), (override));
    MOCK_METHOD((void), on_new_block, (const remote::StateChangeBatch&), (override));
    MOCK_METHOD((size_t), latest_data_size, (), (override));
    MOCK_METHOD((size_t), latest_code_size, (), (override));
    MOCK_METHOD((uint64_t), state_hit_count, (), (const));
    MOCK_METHOD((uint64_t), state_miss_count, (), (const));
    MOCK_METHOD((uint64_t), state_key_count, (), (const));
    MOCK_METHOD((uint64_t), state_eviction_count, (), (const));
    MOCK_METHOD((uint64_t), code_hit_count, (), (const));
    MOCK_METHOD((uint64_t), code_miss_count, (), (const));
    MOCK_METHOD((uint64_t), code_key_count, (), (const));
    MOCK_METHOD((uint64_t), code_eviction_count, (), (const));
};

}  // namespace silkworm::rpc::test
