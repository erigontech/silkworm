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

#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <gmock/gmock.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/ethdb/cursor.hpp>

namespace silkworm::rpc::test {

class MockCursor : public ethdb::Cursor {
  public:
    MOCK_METHOD((uint32_t), cursor_id, (), (const));
    MOCK_METHOD((Task<void>), open_cursor, (const std::string& table_name, bool is_dup_sorted));
    MOCK_METHOD((Task<KeyValue>), seek, (silkworm::ByteView key));
    MOCK_METHOD((Task<KeyValue>), seek_exact, (silkworm::ByteView key));
    MOCK_METHOD((Task<KeyValue>), next, ());
    MOCK_METHOD((Task<KeyValue>), previous, ());
    MOCK_METHOD((Task<void>), close_cursor, ());
};

class MockCursorDupSort : public ethdb::CursorDupSort {
  public:
    MOCK_METHOD((uint32_t), cursor_id, (), (const));
    MOCK_METHOD((Task<void>), open_cursor, (const std::string& table_name, bool is_dup_sorted));
    MOCK_METHOD((Task<KeyValue>), seek, (silkworm::ByteView key));
    MOCK_METHOD((Task<KeyValue>), seek_exact, (silkworm::ByteView key));
    MOCK_METHOD((Task<KeyValue>), next, ());
    MOCK_METHOD((Task<KeyValue>), previous, ());
    MOCK_METHOD((Task<KeyValue>), next_dup, ());
    MOCK_METHOD((Task<void>), close_cursor, ());
    MOCK_METHOD((Task<silkworm::Bytes>), seek_both, (silkworm::ByteView, silkworm::ByteView));
    MOCK_METHOD((Task<KeyValue>), seek_both_exact, (silkworm::ByteView, silkworm::ByteView));
};

}  // namespace silkworm::rpc::test
