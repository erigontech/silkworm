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

class MockROTxn : public ROTxn {
  public:
    explicit MockROTxn() : ROTxn(txn_) {}

    MOCK_METHOD((bool), is_open, (), (const));
    MOCK_METHOD((mdbx::env), db, (), (const));
    MOCK_METHOD((std::unique_ptr<ROCursor>), ro_cursor, (const MapConfig&));
    MOCK_METHOD((std::unique_ptr<ROCursorDupSort>), ro_cursor_dup_sort, (const MapConfig&));
    MOCK_METHOD((void), abort, ());

  private:
    ::mdbx::txn txn_;
};

}  // namespace silkworm::db::test_util
