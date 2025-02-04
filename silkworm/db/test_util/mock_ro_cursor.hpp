/*
   Copyright 2024 The Silkworm Authors

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

#include <gmock/gmock.h>

#include <silkworm/db/datastore/kvdb/mdbx.hpp>

namespace silkworm::db::test_util {

class MockROCursor : public datastore::kvdb::ROCursor {
  public:
    using CursorResult = datastore::kvdb::CursorResult;
    using Slice = datastore::kvdb::Slice;

    MOCK_METHOD((void), bind, (datastore::kvdb::ROTxn&, const datastore::kvdb::MapConfig&), (override));
    MOCK_METHOD((std::unique_ptr<ROCursor>), clone, (), (override));
    MOCK_METHOD((size_t), size, (), (const, override));
    MOCK_METHOD((bool), empty, (), (const));
    MOCK_METHOD((bool), is_multi_value, (), (const, override));
    MOCK_METHOD((bool), is_dangling, (), (const, override));
    MOCK_METHOD((::mdbx::map_handle), map, (), (const, override));
    MOCK_METHOD((CursorResult), to_first, (), (override));
    MOCK_METHOD((CursorResult), to_first, (bool), (override));
    MOCK_METHOD((CursorResult), to_previous, (), (override));
    MOCK_METHOD((CursorResult), to_previous, (bool), (override));
    MOCK_METHOD((CursorResult), current, (), (const, override));
    MOCK_METHOD((CursorResult), current, (bool), (const, override));
    MOCK_METHOD((CursorResult), to_next, (), (override));
    MOCK_METHOD((CursorResult), to_next, (bool), (override));
    MOCK_METHOD((CursorResult), to_last, (), (override));
    MOCK_METHOD((CursorResult), to_last, (bool), (override));
    MOCK_METHOD((CursorResult), find, (const Slice&), (override));
    MOCK_METHOD((CursorResult), find, (const Slice&, bool), (override));
    MOCK_METHOD((CursorResult), lower_bound, (const Slice&), (override));
    MOCK_METHOD((CursorResult), lower_bound, (const Slice&, bool), (override));
    MOCK_METHOD((datastore::kvdb::MoveResult), move, (datastore::kvdb::MoveOperation, bool), (override));
    MOCK_METHOD((datastore::kvdb::MoveResult), move, (datastore::kvdb::MoveOperation, const Slice&, bool), (override));
    MOCK_METHOD((bool), seek, (const Slice&), (override));
    MOCK_METHOD((bool), eof, (), (const, override));
    MOCK_METHOD((bool), on_first, (), (const, override));
    MOCK_METHOD((bool), on_last, (), (const, override));
};

}  // namespace silkworm::db::test_util
