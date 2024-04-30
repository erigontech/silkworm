/*
   Copyright 2023 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#pragma once

#include <cstddef>
#include <memory>
#include <optional>

#include <silkworm/infra/concurrency/task.hpp>

#include <gmock/gmock.h>

#include <silkworm/core/common/util.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/ethdb/kv/state_cache.hpp>
#include <silkworm/rpc/ethdb/transaction.hpp>

namespace silkworm::rpc::test {

class MockBlockCache : public silkworm::BlockCache {
  public:
    MOCK_METHOD((std::optional<std::shared_ptr<silkworm::BlockWithHash>>), get, (const evmc::bytes32&), ());
    MOCK_METHOD((void), insert, (const evmc::bytes32&, const std::shared_ptr<silkworm::BlockWithHash>), ());
};

}  // namespace silkworm::rpc::test
