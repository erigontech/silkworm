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

#include <filesystem>

#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/db/mdbx/mdbx.hpp>

namespace silkworm::db::test_util {

std::filesystem::path get_tests_dir();

InMemoryState populate_genesis(db::RWTxn& txn, const std::filesystem::path& tests_dir);

void populate_blocks(db::RWTxn& txn, const std::filesystem::path& tests_dir, InMemoryState& state_buffer);

class TestDatabaseContext {
  public:
    TestDatabaseContext();

    ~TestDatabaseContext() {
        auto db_path = db.get_path();
        db.close();
        std::filesystem::remove_all(db_path);
    }

    mdbx::env_managed db;
};

}  // namespace silkworm::db::test_util
