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

    TEST_CASE("header persistence") {
        test::Context context;
        auto& txn{context.txn()};

        bool allow_exceptions = false;

        auto source_data = silkworm::read_genesis_data(silkworm::kMainnetConfig.chain_id);
        auto genesis_json = nlohmann::json::parse(source_data, nullptr, allow_exceptions);
        db::initialize_genesis(txn, genesis_json, allow_exceptions);
        context.commit_and_renew_txn();

        /* status:
         *         h0
         * input:
         *         h0 <----- h1
         */
        SECTION("one header after the genesis") {
            Db::ReadWriteAccess::Tx tx(txn);    // sub transaction

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
            auto header1_hash = header1.hash();

            auto td = header0->difficulty + header1.difficulty;

            pc.persist(header1); // here pc write the header on the db

            // check internal status
            REQUIRE(pc.best_header_changed() == true);
            REQUIRE(pc.highest_height() == 1);
            REQUIRE(pc.highest_hash() == header1_hash);

            // check db content
            REQUIRE(tx.read_head_header_hash() == header1_hash);
            REQUIRE(tx.read_total_difficulty(1, header1.hash()) == td);

            auto header1_in_db = tx.read_header(header1_hash);
            REQUIRE(header1_in_db.has_value());
            REQUIRE(header1_in_db == header1);

            pc.close(); // here pc update the canonical chain on the db

            REQUIRE(tx.read_canonical_hash(1) == header1_hash);
        }

        /* status:
         *         h0
         * input:
         *         h0 <----- h1 <----- h2
         *               |-- h1'
         */
//        SECTION("some header after the genesis") {
//            //Db::ReadWriteAccess::Tx tx(txn);    // sub transaction
//
//            //PersistedChain pc(tx);
//            // todo
//        }

        /* status:
         *        h0
         * input:
        *         h0 <----- h1  <----- h2
        *               |-- h1' <----- h2' <----- h3' (new cononical)
         */
//        SECTION("a header in a secondary chain") {
//            // todo
//        }

        /* status:
         *         h0 <----- h1 <----- h2
         *               |-- h1'
         * input:
        *         h0 <----- h1  <----- h2
        *               |-- h1' <----- h2' <----- h3' (new cononical)
         */
//        SECTION("a forking point in the past") {
//            // todo
//        }
    }

}