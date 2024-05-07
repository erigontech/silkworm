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

#include <silkworm/db/mdbx/mdbx.hpp>

namespace silkworm::db::test_util {

class MockROCursor : public ROCursor {
  public:
    MOCK_METHOD((void), bind, (ROTxn&, const MapConfig&));
    MOCK_METHOD((size_t), size, (), (const));
    MOCK_METHOD((bool), empty, (), (const));
    MOCK_METHOD((bool), is_multi_value, (), (const));
    MOCK_METHOD((bool), is_dangling, (), (const));
    MOCK_METHOD((::mdbx::map_handle), map, (), (const));
    MOCK_METHOD((CursorResult), to_first, ());
    MOCK_METHOD((CursorResult), to_first, (bool));
    MOCK_METHOD((CursorResult), to_previous, ());
    MOCK_METHOD((CursorResult), to_previous, (bool));
    MOCK_METHOD((CursorResult), current, (), (const));
    MOCK_METHOD((CursorResult), current, (bool), (const));
    MOCK_METHOD((CursorResult), to_next, ());
    MOCK_METHOD((CursorResult), to_next, (bool));
    MOCK_METHOD((CursorResult), to_last, ());
    MOCK_METHOD((CursorResult), to_last, (bool));
    MOCK_METHOD((CursorResult), find, (const Slice&));
    MOCK_METHOD((CursorResult), find, (const Slice&, bool));
    MOCK_METHOD((CursorResult), lower_bound, (const Slice&));
    MOCK_METHOD((CursorResult), lower_bound, (const Slice&, bool));
    MOCK_METHOD((MoveResult), move, (MoveOperation, bool));
    MOCK_METHOD((MoveResult), move, (MoveOperation, const Slice&, bool));
    MOCK_METHOD((bool), seek, (const Slice&));
    MOCK_METHOD((bool), eof, (), (const));
    MOCK_METHOD((bool), on_first, (), (const));
    MOCK_METHOD((bool), on_last, (), (const));

    //CursorResult find(const Slice&) override { return CursorResult{{}, {}, false}; }
};

}  // namespace silkworm::db::test_util
