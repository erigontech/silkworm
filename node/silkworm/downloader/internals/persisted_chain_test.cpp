/*
Copyright 2020 The Silkworm Authors

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

#include "persisted_chain.hpp"

#include <silkworm/common/test_context.hpp>
#include <silkworm/chain/genesis.hpp>
#include <silkworm/db/genesis.hpp>

#include <algorithm>
#include <catch2/catch.hpp>

namespace silkworm {

    TEST_CASE("persisted_chain") {
        test::Context context;
        auto& txn{context.txn()};

        bool allow_exceptions = false;

        auto source_data = silkworm::read_genesis_data(silkworm::kMainnetConfig.chain_id);
        auto genesis_json = nlohmann::json::parse(source_data, nullptr, allow_exceptions);
        db::initialize_genesis(txn, genesis_json, allow_exceptions);
        context.commit_and_renew_txn();

        SECTION("canonical hash") {
            Db::ReadWriteAccess::Tx tx(txn);    // warning: sub transaction

            auto header0_hash = tx.read_canonical_hash(0);
            REQUIRE(header0_hash.has_value());

            auto header0 = tx.read_canonical_header(0);
            REQUIRE(header0.has_value());

            PersistedChain pc(tx); // is correct but here FAILS at the moment because initialize_genesis() write total difficulty without rlp encoding

            REQUIRE(pc.unwind_detected() == false);
            REQUIRE(pc.initial_height() == 0);

            BlockHeader header1;
            header1.number = 1;
            header1.difficulty = 17'171'480'576;
            header1.parent_hash = *header0_hash;

            auto td = header0->difficulty + header1.difficulty;

            pc.persist(header1);

            REQUIRE(pc.best_header_changed() == true);
            REQUIRE(pc.highest_height() == 1);
            REQUIRE(pc.highest_hash() == header1.hash());

            REQUIRE(tx.read_canonical_hash(1) == header1.hash());
            REQUIRE(tx.read_total_difficulty(1, header1.hash()) == td);

        }
    }

}