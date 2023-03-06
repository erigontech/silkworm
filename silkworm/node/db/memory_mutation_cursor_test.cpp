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

#include "memory_mutation_cursor.hpp"

#include <catch2/catch.hpp>

#include <silkworm/node/common/test_context.hpp>

namespace silkworm::db {

TEST_CASE("MemoryMutationCursor", "[silkworm][node][db][memory_mutation_cursor]") {
    const TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path() / "main_db"};
    data_dir.deploy();
    db::EnvConfig main_db_config{
        .path = data_dir.chaindata().path().string(),
        .create = true,
        .in_memory = true,
    };
    auto main_env{db::open_env(main_db_config)};
    RWTxn main_txn{main_env};
    MemoryOverlay overlay{tmp_dir.path() / "silkworm_mem_db"};
    MemoryMutation mutation{overlay, &main_txn};
    const MapConfig svt_config{
        .name = "SingleValueTable",
    };
    open_map(main_txn, svt_config);
    open_map(mutation, svt_config);

    SECTION("Create one memory mutation cursor") {
        CHECK_NOTHROW(MemoryMutationCursor{mutation, svt_config});
    }

    SECTION("Create many memory mutation cursors") {
        std::vector<std::unique_ptr<MemoryMutationCursor>> memory_cursors;
        for (int i{0}; i < 10; ++i) {
            CHECK_NOTHROW(memory_cursors.emplace_back(std::make_unique<MemoryMutationCursor>(mutation, svt_config)));
        }
    }

    SECTION("Check initial values") {
        MemoryMutationCursor mutation_cursor{mutation, svt_config};
        CHECK_NOTHROW(!mutation_cursor.is_table_cleared());
        CHECK_NOTHROW(!mutation_cursor.is_entry_deleted(Bytes{}));
    }

    MemoryMutationCursor mutation_cursor{mutation, svt_config};

    SECTION("to_first") {
        // TODO(canepat) placeholder: code to-be-tested not implemented yet
        CHECK_THROWS_AS(mutation_cursor.to_first(), std::invalid_argument);
    }

    SECTION("to_last") {
        // TODO(canepat) placeholder: code to-be-tested not implemented yet
        CHECK_THROWS_AS(mutation_cursor.to_last(), std::invalid_argument);
    }
}

}  // namespace silkworm::db
