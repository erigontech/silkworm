// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <gmock/gmock.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>

namespace silkworm::db::test_util {

class MockStateView : public kv::api::StateView {
  public:
    MOCK_METHOD(bool, empty, (), (const, override));
    MOCK_METHOD((Task<std::optional<Bytes>>), get, (std::string_view, Bytes), (override));
    MOCK_METHOD((Task<std::optional<Bytes>>), get_code, (Bytes), (override));
};

class MockStateCache : public kv::api::StateCache {
  public:
    Task<std::unique_ptr<kv::api::StateView>> get_view(kv::api::Transaction&) override {
        co_return std::make_unique<MockStateView>();
    }
    MOCK_METHOD(void, on_new_block, (const kv::api::StateChangeSet&), (override));
    MOCK_METHOD(size_t, latest_data_size, (), (override));
    MOCK_METHOD(size_t, latest_code_size, (), (override));

    MOCK_METHOD(uint64_t, state_hit_count, (), (const, override));
    MOCK_METHOD(uint64_t, state_miss_count, (), (const, override));
    MOCK_METHOD(uint64_t, state_key_count, (), (const, override));
    MOCK_METHOD(uint64_t, state_eviction_count, (), (const, override));
    MOCK_METHOD(uint64_t, code_hit_count, (), (const, override));
    MOCK_METHOD(uint64_t, code_miss_count, (), (const, override));
    MOCK_METHOD(uint64_t, code_key_count, (), (const, override));
    MOCK_METHOD(uint64_t, code_eviction_count, (), (const, override));

    MOCK_METHOD(Task<ValidationResult>, validate_current_root, (kv::api::Transaction&), (override));
};

}  // namespace silkworm::db::test_util
