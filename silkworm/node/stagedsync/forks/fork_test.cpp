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

#include "fork.hpp"

#include <thread>

#include <boost/asio/io_context.hpp>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/genesis.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/infra/common/environment.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/common/preverified_hashes.hpp>
#include <silkworm/node/test_util/sample_blocks.hpp>
#include <silkworm/node/test_util/temp_chain_data_node_settings.hpp>

#include "main_chain.hpp"

namespace silkworm {

namespace asio = boost::asio;
using namespace silkworm::test_util;
using namespace stagedsync;
using namespace intx;  // just for literals

using execution::api::ValidChain;

class ForkForTest : public Fork {
  public:
    using Fork::canonical_chain_;
    using Fork::current_head_;
    using Fork::Fork;  // NOLINT(cppcoreguidelines-rvalue-reference-param-not-moved)
    using Fork::main_tx_;
    using Fork::memory_db_;
    using Fork::memory_tx_;
    using Fork::pipeline_;
};

TEST_CASE("Fork") {
    SetLogVerbosityGuard log_guard(log::Level::kNone);

    db::test_util::TempChainData context;
    context.add_genesis_data();
    context.commit_txn();

    asio::io_context io;
    asio::executor_work_guard<decltype(io.get_executor())> work{io.get_executor()};

    PreverifiedHashes::current.clear();                           // disable preverified hashes
    Environment::set_stop_before_stage(db::stages::kSendersKey);  // only headers, block hashes and bodies

    NodeSettings node_settings = node::test_util::make_node_settings_from_temp_chain_data(context);
    db::RWAccess db_access{context.env()};
    MainChain main_chain{io, node_settings, db_access};

    main_chain.open();
    auto& tx = main_chain.tx();

    auto header0_hash = db::read_canonical_header_hash(tx, 0);
    REQUIRE(header0_hash.has_value());

    auto header0 = db::read_canonical_header(tx, 0);
    REQUIRE(header0.has_value());

    auto block1 = generate_sample_child_blocks(*header0);
    auto block1_hash = block1->header.hash();

    auto block2 = generate_sample_child_blocks(block1->header);
    // auto block2_hash = block2.header.hash();

    auto block3 = generate_sample_child_blocks(block2->header);
    auto block3_hash = block3->header.hash();

    // inserting & verifying the block
    main_chain.insert_block(*block1);
    main_chain.insert_block(*block2);
    main_chain.insert_block(*block3);
    auto verification = main_chain.verify_chain(block3_hash);

    REQUIRE(holds_alternative<ValidChain>(verification));
    auto valid_chain = std::get<ValidChain>(verification);
    REQUIRE(valid_chain.current_head == BlockId{3, block3_hash});

    REQUIRE(db::stages::read_stage_progress(main_chain.tx(), db::stages::kHeadersKey) == 3);
    REQUIRE(db::stages::read_stage_progress(main_chain.tx(), db::stages::kBlockHashesKey) == 3);
    REQUIRE(db::stages::read_stage_progress(main_chain.tx(), db::stages::kBlockBodiesKey) == 3);

    // confirming the chain
    auto fcu_updated = main_chain.notify_fork_choice_update(block3_hash, block1_hash);
    REQUIRE(fcu_updated);

    auto final_canonical_head = main_chain.last_chosen_head();
    REQUIRE(final_canonical_head == BlockId{3, block3_hash});

    SECTION("creating a fork") {
        std::exception_ptr test_failure;
        auto fork_thread = std::thread([&]() {  // avoid mdbx limitations on txns & threads
            try {
                auto block4 = generate_sample_child_blocks(block3->header);
                auto block4_hash = block4->header.hash();

                BlockId forking_point = main_chain.last_chosen_head();

                ForkForTest fork{forking_point,
                                 db::ROTxnManaged(main_chain.tx().db()),  // this need to be on a different thread than main_chain
                                 node_settings};

                CHECK(db::stages::read_stage_progress(fork.memory_tx_, db::stages::kHeadersKey) == 3);
                CHECK(db::stages::read_stage_progress(fork.memory_tx_, db::stages::kBlockHashesKey) == 3);
                CHECK(db::stages::read_stage_progress(fork.memory_tx_, db::stages::kBlockBodiesKey) == 3);

                CHECK(!fork.head_status().has_value());

                // inserting blocks
                fork.extend_with(*block4);
                CHECK(db::read_header(fork.memory_tx_, 4, block4_hash));

                // verification
                auto fork_verification = fork.verify_chain();  // run pipeline

                REQUIRE(holds_alternative<ValidChain>(fork_verification));
                auto fork_valid_chain = std::get<ValidChain>(fork_verification);
                CHECK(fork_valid_chain.current_head == BlockId{4, block4_hash});

                CHECK(db::stages::read_stage_progress(fork.memory_tx_, db::stages::kHeadersKey) == 4);
                CHECK(db::stages::read_stage_progress(fork.memory_tx_, db::stages::kBlockHashesKey) == 4);
                CHECK(db::stages::read_stage_progress(fork.memory_tx_, db::stages::kBlockBodiesKey) == 4);

                // fork choice
                bool updated = fork.fork_choice(block4_hash, block3_hash);
                CHECK(updated);
                CHECK(fork.current_head() == BlockId{4, block4_hash});
                CHECK((fork.head_status().has_value() && holds_alternative<ValidChain>(*fork.head_status())));

                // close
                fork.close();
            } catch (...) {
                test_failure = std::current_exception();
            }
        });
        fork_thread.join();
        if (test_failure) {
            std::rethrow_exception(test_failure);
        }
    }
}

}  // namespace silkworm