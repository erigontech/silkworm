// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "fork.hpp"

#include <thread>

#include <boost/asio/io_context.hpp>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/test_util/sample_blocks.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/infra/common/environment.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/test_util/make_stages_factory.hpp>
#include <silkworm/node/test_util/temp_chain_data_node_settings.hpp>

#include "main_chain.hpp"

namespace silkworm {

namespace asio = boost::asio;
using namespace silkworm::test_util;
using namespace stagedsync;
using namespace intx;  // just for literals

using execution::api::ValidChain;
using silkworm::stagedsync::test_util::make_stages_factory;

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
    db::test_util::TempChainDataStore context;
    context.add_genesis_data();
    context.commit_txn();

    db::DataModelFactory data_model_factory = context.data_model_factory();

    asio::io_context ioc;
    asio::executor_work_guard<decltype(ioc.get_executor())> work{ioc.get_executor()};

    Environment::set_stop_before_stage(db::stages::kSendersKey);  // only headers, block hashes and bodies

    NodeSettings node_settings = node::test_util::make_node_settings_from_temp_chain_data(context);
    datastore::kvdb::RWAccess db_access = context.chaindata_rw();

    MainChain main_chain{
        ioc.get_executor(),
        node_settings,
        data_model_factory,
        /* log_timer_factory = */ std::nullopt,
        make_stages_factory(node_settings, data_model_factory),
        db_access,
    };

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

                ForkForTest fork{
                    forking_point,
                    datastore::kvdb::ROTxnManaged(main_chain.tx().db()),  // this need to be on a different thread than main_chain
                    data_model_factory,
                    /* log_timer_factory = */ std::nullopt,
                    main_chain.stages_factory(),
                    node_settings.data_directory->forks().path(),
                };

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