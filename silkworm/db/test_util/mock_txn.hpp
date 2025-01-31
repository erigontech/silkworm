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

class MockROTxn : public datastore::kvdb::ROTxn {
  public:
    explicit MockROTxn() : datastore::kvdb::ROTxn(txn_) {}

    MOCK_METHOD((bool), is_open, (), (const, override));
    MOCK_METHOD((mdbx::env), db, (), (const, override));
    MOCK_METHOD((std::unique_ptr<datastore::kvdb::ROCursor>), ro_cursor, (const datastore::kvdb::MapConfig&), (override));
    MOCK_METHOD((std::unique_ptr<datastore::kvdb::ROCursorDupSort>), ro_cursor_dup_sort, (const datastore::kvdb::MapConfig&), (override));
    MOCK_METHOD((void), abort, (), (override));

  private:
    ::mdbx::txn txn_;
};

class MockRwTxn : public datastore::kvdb::RWTxn {
  public:
    explicit MockRwTxn() : datastore::kvdb::RWTxn(txn_) {}

    MOCK_METHOD((bool), is_open, (), (const, override));
    MOCK_METHOD((mdbx::env), db, (), (const, override));
    MOCK_METHOD((std::unique_ptr<datastore::kvdb::ROCursor>), ro_cursor, (const datastore::kvdb::MapConfig&), (override));
    MOCK_METHOD((std::unique_ptr<datastore::kvdb::ROCursorDupSort>), ro_cursor_dup_sort, (const datastore::kvdb::MapConfig&), (override));
    MOCK_METHOD((std::unique_ptr<datastore::kvdb::RWCursor>), rw_cursor, (const datastore::kvdb::MapConfig&), ());
    MOCK_METHOD((std::unique_ptr<datastore::kvdb::RWCursorDupSort>), rw_cursor_dup_sort, (const datastore::kvdb::MapConfig&), ());
    MOCK_METHOD((void), commit, (), ());
    MOCK_METHOD((void), abort, (), (override));
    MOCK_METHOD((void), commit_and_renew, (), ());
    MOCK_METHOD((void), commit_and_stop, (), ());

  private:
    ::mdbx::txn txn_;
    // silkworm::datastore::kvdb::RWCursor aa;
};

}  // namespace silkworm::db::test_util
