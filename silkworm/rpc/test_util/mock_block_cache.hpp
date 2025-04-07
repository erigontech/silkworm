// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <optional>

#include <silkworm/infra/concurrency/task.hpp>

#include <gmock/gmock.h>

#include <silkworm/db/kv/api/state_cache.hpp>

namespace silkworm::rpc::test {

class MockBlockCache : public silkworm::BlockCache {
  public:
    MOCK_METHOD((std::optional<std::shared_ptr<silkworm::BlockWithHash>>), get, (const evmc::bytes32&), ());
    MOCK_METHOD((void), insert, (const evmc::bytes32&, const std::shared_ptr<silkworm::BlockWithHash>), ());
};

}  // namespace silkworm::rpc::test
