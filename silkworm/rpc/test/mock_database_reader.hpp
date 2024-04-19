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

#include <memory>
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <gmock/gmock.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/rawdb/accessors.hpp>

namespace silkworm::rpc::test {

class MockDatabaseReader : public core::rawdb::DatabaseReader {
  public:
    MOCK_METHOD((Task<KeyValue>), get, (const std::string&, silkworm::ByteView), (const));
    MOCK_METHOD((Task<silkworm::Bytes>), get_one, (const std::string&, silkworm::ByteView), (const));
    MOCK_METHOD((Task<std::optional<silkworm::Bytes>>), get_both_range,
                (const std::string&, silkworm::ByteView, silkworm::ByteView), (const));
    MOCK_METHOD((Task<void>), walk, (const std::string&, silkworm::ByteView, uint32_t, core::rawdb::Walker),
                (const));
    MOCK_METHOD((Task<void>), walk_worker, (const std::string&, silkworm::ByteView, uint32_t, core::rawdb::Worker, uint32_t max_records),
                (const));
    MOCK_METHOD((Task<void>), for_prefix, (const std::string&, silkworm::ByteView, core::rawdb::Walker),
                (const));
};

}  // namespace silkworm::rpc::test
