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

#include "header_retrieval.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/test_util/make_repository.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>

namespace silkworm {

TEST_CASE("HeaderRetrieval") {
    db::test_util::TempChainData context;
    context.add_genesis_data();
    context.commit_txn();

    snapshots::SnapshotRepository repository = db::test_util::make_repository();

    db::ROTxnManaged tx = db::ROAccess{context.env()}.start_ro_tx();
    db::DataModel data_model{tx, repository};

    HeaderRetrieval header_retrieval{data_model};

    SECTION("recover_by_hash") {
        const auto headers{header_retrieval.recover_by_hash({}, 1, 0, false)};
    }
    SECTION("recover_by_number") {
        const auto headers{header_retrieval.recover_by_number({}, 1, 0, false)};
    }
}

}  // namespace silkworm