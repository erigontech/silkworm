// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
