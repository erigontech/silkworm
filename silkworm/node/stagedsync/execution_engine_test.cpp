// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "execution_engine.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/test_util/sample_blocks.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/db/test_util/test_database_context.hpp>
#include <silkworm/infra/common/environment.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/infra/test_util/task_runner.hpp>
#include <silkworm/node/common/node_settings.hpp>
#include <silkworm/node/test_util/make_stages_factory.hpp>
#include <silkworm/node/test_util/temp_chain_data_node_settings.hpp>

namespace silkworm {

using namespace silkworm::db;
using namespace stagedsync;

using execution::api::InvalidChain;
using execution::api::ValidationError;
using execution::api::ValidChain;

using silkworm::stagedsync::test_util::make_stages_factory;
using silkworm::test_util::generate_sample_child_blocks;
using silkworm::test_util::TaskRunner;

class ExecutionEngineForTest : public stagedsync::ExecutionEngine {
  public:
    using stagedsync::ExecutionEngine::ExecutionEngine;
    MainChain& main_chain() { return main_chain_; }
};

TEST_CASE("ExecutionEngine Integration Test", "[node][execution][execution_engine]") {
    TemporaryDirectory tmp_dir;
    TaskRunner runner;
    Environment::set_stop_before_stage(stages::kSendersKey);  // only headers, block hashes and bodies

    db::test_util::TestDataStore db_context{tmp_dir};
    db::DataModelFactory data_model_factory = db_context.data_model_factory();

    auto node_settings = NodeSettings{
        .data_directory = std::make_unique<DataDirectory>(tmp_dir.path(), false),
        .chain_config = db_context.get_chain_config(),
        .parallel_fork_tracking_enabled = false,
        .keep_db_txn_open = true,
    };

    auto db_access = db_context.chaindata_rw();

    ExecutionEngineForTest exec_engine{
        runner.executor(),
        node_settings,
        data_model_factory,
        /* log_timer_factory = */ std::nullopt,
        make_stages_factory(node_settings, data_model_factory),
        db_access,
    };
    exec_engine.open();

    auto& tx = exec_engine.main_chain().tx();  // mdbx refuses to open a ROTxn when there is a RWTxn in the same thread

    const auto header0_hash = exec_engine.get_canonical_hash(0).value();
    const silkworm::Hash header1_hash{0x7cb4dd3daba1f739d0c1ec7d998b4a2f6fd83019116455afa54ca4f49dfa0ad4_bytes32};

    auto const current_head_id = exec_engine.last_finalized_block();
    auto const current_head = exec_engine.get_header(current_head_id.block_num, current_head_id.hash).value();

    SECTION("get_block_num") {
        auto block_num = exec_engine.get_block_num(header1_hash);
        REQUIRE(block_num.has_value());
        CHECK(*block_num == 1);
    }

    SECTION("get_header by hash") {
        auto db_block_num = silkworm::read_block_num(tx, header1_hash);
        silkworm::Block db_block;
        auto db_read = silkworm::read_block(tx, header1_hash, *db_block_num, db_block);
        REQUIRE(db_read);

        auto header1 = exec_engine.get_header(header1_hash);
        REQUIRE(header1.has_value());
        CHECK(header1->hash() == db_block.header.hash());
        CHECK(header1->number == 1);
    }

    SECTION("get_header by hash not found") {
        const silkworm::Hash header_not_found_hash{0x00000000000000000000000000000000000000000000000000000000deadbeef_bytes32};

        auto db_block_num = silkworm::read_block_num(tx, header_not_found_hash);
        silkworm::Block db_block;
        auto db_read = silkworm::read_block(tx, header_not_found_hash, *db_block_num, db_block);
        REQUIRE(!db_read);

        auto header = exec_engine.get_header(header_not_found_hash);
        REQUIRE(!header.has_value());
    }

    SECTION("get_header by number") {
        auto header1 = exec_engine.get_header(1, header1_hash);
        REQUIRE(header1.has_value());
        CHECK(header1->hash() == header1_hash);
        CHECK(header1->number == 1);
    }

    SECTION("get_body by hash") {
        auto body = exec_engine.get_body(header1_hash);
        REQUIRE(body.has_value());
        CHECK(body->transactions.size() == 1);
    }

    SECTION("get_last_headers shows numbers from the head down") {
        auto headers = exec_engine.get_last_headers(2);
        REQUIRE(headers.size() == 2);
        CHECK(headers[0].number == 9);
        CHECK(headers[1].number == 8);
    }

    SECTION("get_header_td returns correct total difficulty for genesis block") {
        auto td = exec_engine.get_header_td(header0_hash, std::nullopt);
        REQUIRE(td.has_value());
        CHECK(*td == 1);
    }

    SECTION("last blocks points to head block") {
        auto block_progress = exec_engine.block_progress();
        CHECK(block_progress == 9);

        auto last_fork_choice = exec_engine.last_fork_choice();
        CHECK(last_fork_choice.block_num == 9);

        auto last_finalized_block = exec_engine.last_finalized_block();
        CHECK(last_finalized_block.block_num == 9);

        auto last_safe_block = exec_engine.last_safe_block();
        CHECK(last_safe_block.block_num == 0);
    }

    SECTION("insert_block does not update the head block and fork choice") {
        auto new_block = generate_sample_child_blocks(current_head);

        auto current_progress = exec_engine.block_progress();
        CHECK(current_progress == 9);
        auto current_fork_choice = exec_engine.last_fork_choice();
        CHECK(current_fork_choice == current_head_id);

        exec_engine.insert_block(new_block);

        auto new_head_id = exec_engine.last_finalized_block();
        CHECK(new_head_id == current_head_id);
        auto new_progress = exec_engine.block_progress();
        CHECK(new_progress == 10);
        auto new_fork_choice = exec_engine.last_fork_choice();
        CHECK(new_fork_choice == current_head_id);
    }

    SECTION("insert_block with invalid block doesn't create valid chain") {
        auto new_block = std::make_shared<Block>();
        new_block->header.number = current_head.number + 1;
        new_block->header.difficulty = 17'171'480'576;  // a random value
        new_block->header.parent_hash = current_head.hash();
        new_block->ommers.push_back(BlockHeader{});  // generates error InvalidOmmerHeader
        auto new_block_hash = new_block->header.hash();

        auto block_inserted = exec_engine.insert_block(new_block);

        REQUIRE(block_inserted);

        auto is_canonical = exec_engine.is_canonical(new_block_hash);
        CHECK(!is_canonical);

        auto verification = runner.run(exec_engine.verify_chain(new_block_hash));
        CHECK(!holds_alternative<ValidationError>(verification));
        REQUIRE(holds_alternative<InvalidChain>(verification));
        auto invalid_chain = std::get<InvalidChain>(verification);
        CHECK(invalid_chain.unwind_point == current_head_id);
        CHECK(invalid_chain.bad_block.has_value());
        CHECK(invalid_chain.bad_block.value() == new_block_hash);
        CHECK(invalid_chain.bad_headers.size() == 1);
    }

    // Test scenario:
    // c7 -> c8 -> c9 -> f1 -> f2 -> f3
    SECTION("insert_blocks with valid blocks creates valid chain for each block") {
        auto block1 = generate_sample_child_blocks(current_head);
        auto block2 = generate_sample_child_blocks(block1->header);
        auto block3 = generate_sample_child_blocks(block2->header);

        auto blocks = std::vector<std::shared_ptr<Block>>{block1, block2, block3};
        exec_engine.insert_blocks(blocks);

        auto block1_hash = block1->header.hash();
        auto block2_hash = block2->header.hash();
        auto block3_hash = block3->header.hash();

        auto is_canonical1 = exec_engine.is_canonical(block1_hash);
        CHECK(!is_canonical1);
        auto is_canonical2 = exec_engine.is_canonical(block2_hash);
        CHECK(!is_canonical2);
        auto is_canonical3 = exec_engine.is_canonical(block3_hash);
        CHECK(!is_canonical3);

        auto verification1 = runner.run(exec_engine.verify_chain(block1_hash));
        CHECK(!holds_alternative<ValidationError>(verification1));
        REQUIRE(holds_alternative<ValidChain>(verification1));
        auto valid_chain1 = std::get<ValidChain>(verification1);
        CHECK(valid_chain1.current_head == BlockId{10, block1_hash});

        auto verification2 = runner.run(exec_engine.verify_chain(block2_hash));
        CHECK(!holds_alternative<ValidationError>(verification2));
        REQUIRE(holds_alternative<ValidChain>(verification2));
        auto valid_chain2 = std::get<ValidChain>(verification2);
        CHECK(valid_chain2.current_head == BlockId{11, block2_hash});

        auto verification3 = runner.run(exec_engine.verify_chain(block3_hash));
        CHECK(!holds_alternative<ValidationError>(verification3));
        REQUIRE(holds_alternative<ValidChain>(verification3));
        auto valid_chain3 = std::get<ValidChain>(verification3);
        CHECK(valid_chain3.current_head == BlockId{12, block3_hash});
    }

    SECTION("get_header for non-canonical blocks") {
        auto new_block = generate_sample_child_blocks(current_head);
        exec_engine.insert_block(new_block);

        auto new_block_hash = new_block->header.hash();

        // canonical
        auto header1 = exec_engine.get_header(header1_hash);
        REQUIRE(header1.has_value());
        CHECK(header1->hash() == header1_hash);
        CHECK(header1->number == 1);

        header1 = exec_engine.get_header(1, header1_hash);
        REQUIRE(header1.has_value());
        CHECK(header1->hash() == header1_hash);
        CHECK(header1->number == 1);

        // non-canonical
        auto header10 = exec_engine.get_header(new_block_hash);
        REQUIRE(header10.has_value());
        CHECK(header10->hash() == new_block_hash);
        CHECK(header10->number == 10);

        header10 = exec_engine.get_header(10, new_block_hash);
        REQUIRE(header10.has_value());
        CHECK(header10->hash() == new_block_hash);
        CHECK(header10->number == 10);
    }

    SECTION("get_body for non-canonical blocks") {
        auto new_block = generate_sample_child_blocks(current_head);
        exec_engine.insert_block(new_block);

        auto new_block_hash = new_block->header.hash();

        // canonical
        auto body1 = exec_engine.get_body(header1_hash);
        REQUIRE(body1.has_value());

        // non-canonical
        auto body10 = exec_engine.get_body(new_block_hash);
        REQUIRE(body1.has_value());
    }

    SECTION("get_block_num for non-canonical blocks") {
        auto new_block = generate_sample_child_blocks(current_head);
        exec_engine.insert_block(new_block);

        auto new_block_hash = new_block->header.hash();

        // canonical
        auto block_num1 = exec_engine.get_block_num(header1_hash);
        REQUIRE(block_num1.has_value());
        CHECK(*block_num1 == 1);

        // non-canonical
        auto block_num10 = exec_engine.get_block_num(new_block_hash);
        REQUIRE(block_num10.has_value());
        CHECK(*block_num10 == 10);
    }

    SECTION("get_canonical_* functions returns value only for canonical blocks") {
        auto new_block = generate_sample_child_blocks(current_head);
        exec_engine.insert_block(new_block);
        auto new_block_hash = new_block->header.hash();

        // get_canonical_header()
        auto header1 = exec_engine.get_canonical_header(1);
        REQUIRE(header1.has_value());
        CHECK(header1->hash() == header1_hash);
        CHECK(header1->number == 1);

        auto header10 = exec_engine.get_canonical_header(10);
        REQUIRE(!header10.has_value());

        // get_canonical_hash()
        auto hash1 = exec_engine.get_canonical_hash(1);
        REQUIRE(hash1.has_value());
        CHECK(*hash1 == header1_hash);

        auto hash10 = exec_engine.get_canonical_hash(10);
        REQUIRE(!hash10.has_value());

        // get_canonical_body()
        auto body1 = exec_engine.get_canonical_body(1);
        REQUIRE(body1.has_value());

        auto body10 = exec_engine.get_canonical_body(10);
        REQUIRE(!body10.has_value());

        // is_canonical()
        auto is_canonical1 = exec_engine.is_canonical(header1_hash);
        CHECK(is_canonical1);

        auto is_canonical10 = exec_engine.is_canonical(new_block_hash);
        CHECK(!is_canonical10);
    }

    SECTION("notify_fork_choice_update single block without prior verification") {
        auto new_block = generate_sample_child_blocks(current_head);
        exec_engine.insert_block(new_block);

        auto new_block_hash = new_block->header.hash();

        auto fcu_updated = exec_engine.notify_fork_choice_update(new_block_hash, {}, {});
        CHECK(fcu_updated);

        auto new_head_id = exec_engine.last_finalized_block();
        CHECK(new_head_id.block_num == 9);
        auto new_progress = exec_engine.block_progress();
        CHECK(new_progress == 10);
        auto new_fork_choice = exec_engine.last_fork_choice();
        CHECK(new_fork_choice.block_num == 10);

        auto is_new_block_canonical = exec_engine.is_canonical(new_block_hash);
        CHECK(is_new_block_canonical);
    }

    SECTION("notify_fork_choice_update single block with prior verification") {
        auto new_block = generate_sample_child_blocks(current_head);
        exec_engine.insert_block(new_block);

        auto new_block_hash = new_block->header.hash();

        auto verification = runner.run(exec_engine.verify_chain(new_block_hash));
        REQUIRE(holds_alternative<ValidChain>(verification));

        auto fcu_updated = exec_engine.notify_fork_choice_update(new_block_hash, {}, {});
        CHECK(fcu_updated);

        auto new_head_id = exec_engine.last_finalized_block();
        CHECK(new_head_id.block_num == 9);
        auto new_progress = exec_engine.block_progress();
        CHECK(new_progress == 10);
        auto new_fork_choice = exec_engine.last_fork_choice();
        CHECK(new_fork_choice.block_num == 10);

        auto is_new_block_canonical = exec_engine.is_canonical(new_block_hash);
        CHECK(is_new_block_canonical);
    }

    SECTION("notify_fork_choice_update single block updates last_finalized_block and last_safe_block") {
        auto new_block = generate_sample_child_blocks(current_head);
        exec_engine.insert_block(new_block);

        auto new_block_hash = new_block->header.hash();

        auto fcu_updated = exec_engine.notify_fork_choice_update(new_block_hash, current_head_id.hash, current_head_id.hash);
        CHECK(fcu_updated);

        auto new_head_id = exec_engine.last_finalized_block();
        CHECK(new_head_id.block_num == 9);
        auto new_progress = exec_engine.block_progress();
        CHECK(new_progress == 10);
        auto new_fork_choice = exec_engine.last_fork_choice();
        CHECK(new_fork_choice.block_num == 10);
        auto new_safe_block = exec_engine.last_safe_block();
        CHECK(new_safe_block.block_num == 9);
    }

    SECTION("notify_fork_choice_update with multiple blocks using the first block as the head") {
        auto block1 = generate_sample_child_blocks(current_head);
        auto block2 = generate_sample_child_blocks(block1->header);
        auto block3 = generate_sample_child_blocks(block2->header);

        auto blocks = std::vector<std::shared_ptr<Block>>{block1, block2, block3};
        exec_engine.insert_blocks(blocks);

        auto block1_hash = block1->header.hash();
        auto block2_hash = block2->header.hash();
        auto block3_hash = block3->header.hash();

        runner.run(exec_engine.verify_chain(block1_hash));
        runner.run(exec_engine.verify_chain(block2_hash));
        runner.run(exec_engine.verify_chain(block3_hash));

        auto fcu_updated = exec_engine.notify_fork_choice_update(block1_hash, {}, {});
        CHECK(fcu_updated);

        auto new_head_id = exec_engine.last_finalized_block();
        CHECK(new_head_id.block_num == 9);
        auto new_progress = exec_engine.block_progress();
        CHECK(new_progress == 12);
        auto new_fork_choice = exec_engine.last_fork_choice();
        CHECK(new_fork_choice.block_num == 10);

        auto is_block1_canonical = exec_engine.is_canonical(block1_hash);
        CHECK(is_block1_canonical);
        auto is_block2_canonical = exec_engine.is_canonical(block2_hash);
        CHECK(!is_block2_canonical);
        auto is_block3_canonical = exec_engine.is_canonical(block3_hash);
        CHECK(!is_block3_canonical);
    }

    SECTION("notify_fork_choice_update with multiple blocks using the last block as the head") {
        auto block1 = generate_sample_child_blocks(current_head);
        auto block2 = generate_sample_child_blocks(block1->header);
        auto block3 = generate_sample_child_blocks(block2->header);

        auto blocks = std::vector<std::shared_ptr<Block>>{block1, block2, block3};
        exec_engine.insert_blocks(blocks);

        auto block1_hash = block1->header.hash();
        auto block2_hash = block2->header.hash();
        auto block3_hash = block3->header.hash();

        runner.run(exec_engine.verify_chain(block1_hash));
        runner.run(exec_engine.verify_chain(block2_hash));
        runner.run(exec_engine.verify_chain(block3_hash));

        auto fcu_updated = exec_engine.notify_fork_choice_update(block3_hash, {}, {});
        CHECK(fcu_updated);

        auto new_head_id = exec_engine.last_finalized_block();
        CHECK(new_head_id.block_num == 9);
        auto new_progress = exec_engine.block_progress();
        CHECK(new_progress == 12);
        auto new_fork_choice = exec_engine.last_fork_choice();
        CHECK(new_fork_choice.block_num == 12);

        auto is_block1_canonical = exec_engine.is_canonical(block1_hash);
        CHECK(is_block1_canonical);
        auto is_block2_canonical = exec_engine.is_canonical(block2_hash);
        CHECK(is_block2_canonical);
        auto is_block3_canonical = exec_engine.is_canonical(block3_hash);
        CHECK(is_block3_canonical);
    }

    SECTION("notify_fork_choice_update consecutive calls with the same block") {
        auto new_block = generate_sample_child_blocks(current_head);
        exec_engine.insert_block(new_block);

        auto new_block_hash = new_block->header.hash();

        auto fcu_updated = exec_engine.notify_fork_choice_update(new_block_hash, {}, {});
        CHECK(fcu_updated);

        auto new_head_id = exec_engine.last_finalized_block();
        CHECK(new_head_id.block_num == 9);
        auto new_progress = exec_engine.block_progress();
        CHECK(new_progress == 10);
        auto new_fork_choice = exec_engine.last_fork_choice();
        CHECK(new_fork_choice.block_num == 10);

        auto is_new_block_canonical = exec_engine.is_canonical(new_block_hash);
        CHECK(is_new_block_canonical);

        fcu_updated = exec_engine.notify_fork_choice_update(new_block_hash, {}, {});
        CHECK(fcu_updated);  //! updates despite the same block

        new_head_id = exec_engine.last_finalized_block();
        CHECK(new_head_id.block_num == 9);
        new_progress = exec_engine.block_progress();
        CHECK(new_progress == 10);
        new_fork_choice = exec_engine.last_fork_choice();
        CHECK(new_fork_choice.block_num == 10);
    }

    SECTION("notify_fork_choice_update consecutive calls with different blocks") {
        auto new_block1 = generate_sample_child_blocks(current_head);
        exec_engine.insert_block(new_block1);

        auto new_block1_hash = new_block1->header.hash();

        auto fcu_updated = exec_engine.notify_fork_choice_update(new_block1_hash, {}, {});
        CHECK(fcu_updated);

        auto new_head_id = exec_engine.last_finalized_block();
        CHECK(new_head_id.block_num == 9);
        auto new_progress = exec_engine.block_progress();
        CHECK(new_progress == 10);
        auto new_fork_choice = exec_engine.last_fork_choice();
        CHECK(new_fork_choice.block_num == 10);

        auto is_new_block1_canonical = exec_engine.is_canonical(new_block1_hash);
        CHECK(is_new_block1_canonical);

        auto new_block1_header = exec_engine.get_header(10, new_block1_hash);
        REQUIRE(new_block1_header.has_value());

        auto new_block2 = generate_sample_child_blocks(*new_block1_header);
        exec_engine.insert_block(new_block2);

        auto new_block2_hash = new_block2->header.hash();

        fcu_updated = exec_engine.notify_fork_choice_update(new_block2_hash, {}, {});
        CHECK(fcu_updated);

        new_head_id = exec_engine.last_finalized_block();
        CHECK(new_head_id.block_num == 9);
        new_progress = exec_engine.block_progress();
        CHECK(new_progress == 11);
        new_fork_choice = exec_engine.last_fork_choice();
        CHECK(new_fork_choice.block_num == 11);

        auto is_new_block2_canonical = exec_engine.is_canonical(new_block2_hash);
        CHECK(is_new_block2_canonical);
    }

    // Test scenario:
    //                  ↗  f1a -> f1b (fork 1) => fcu
    //  c7 -> c8 -> c9
    //                  ↘  f2a -> f2b (fork 2)
    SECTION("creates and verifies two forks, chooses first") {
        auto block1a = generate_sample_child_blocks(current_head);
        block1a->header.difficulty = 17'171'480'576;  // a random value
        auto block1b = generate_sample_child_blocks(block1a->header);

        auto block2a = generate_sample_child_blocks(current_head);
        block2a->header.difficulty = 17'171'480'577;  // a random value
        auto block2b = generate_sample_child_blocks(block2a->header);

        auto blocks = std::vector<std::shared_ptr<Block>>{block1a, block1b, block2a, block2b};
        exec_engine.insert_blocks(blocks);

        auto block1a_hash = block1a->header.hash();
        auto block1b_hash = block1b->header.hash();
        auto block2a_hash = block2a->header.hash();
        auto block2b_hash = block2b->header.hash();

        auto verification1 = runner.run(exec_engine.verify_chain(block1b_hash));
        CHECK(!holds_alternative<ValidationError>(verification1));
        REQUIRE(holds_alternative<ValidChain>(verification1));

        auto verification2 = runner.run(exec_engine.verify_chain(block2b_hash));
        CHECK(!holds_alternative<ValidationError>(verification2));
        REQUIRE(holds_alternative<ValidChain>(verification2));

        auto fcu_updated = exec_engine.notify_fork_choice_update(block1b_hash, current_head_id.hash, {});
        CHECK(fcu_updated);

        auto new_head_id = exec_engine.last_finalized_block();
        CHECK(new_head_id.block_num == 9);
        auto new_progress = exec_engine.block_progress();
        CHECK(new_progress == 11);
        auto new_fork_choice = exec_engine.last_fork_choice();
        CHECK(new_fork_choice.block_num == 11);

        auto is_block1_canonical = exec_engine.is_canonical(block1a_hash);
        CHECK(is_block1_canonical);
        auto is_block2_canonical = exec_engine.is_canonical(block1b_hash);
        CHECK(is_block2_canonical);
        auto is_block3_canonical = exec_engine.is_canonical(block2a_hash);
        CHECK(!is_block3_canonical);
        auto is_block4_canonical = exec_engine.is_canonical(block2b_hash);
        CHECK(!is_block4_canonical);
    }

    // Test scenario:
    //                  ↗  f1 (10) => fcu
    //  c7 -> c8 -> c9
    //                  ↘  f2 (10)
    SECTION("creates and verifies two single-block forks, chooses first") {
        auto block_f1 = generate_sample_child_blocks(current_head);
        block_f1->header.difficulty = 17'171'480'576;  // a random value

        auto block_f2 = generate_sample_child_blocks(current_head);
        block_f2->header.difficulty = 17'171'480'577;  // a random value

        auto blocks = std::vector<std::shared_ptr<Block>>{block_f1, block_f2};
        exec_engine.insert_blocks(blocks);

        auto block_f1_hash = block_f1->header.hash();
        auto block_f2_hash = block_f2->header.hash();

        INFO(to_hex(block_f1_hash.bytes));

        auto verification1 = runner.run(exec_engine.verify_chain(block_f1_hash));
        CHECK(!holds_alternative<ValidationError>(verification1));
        REQUIRE(holds_alternative<ValidChain>(verification1));

        auto verification2 = runner.run(exec_engine.verify_chain(block_f2_hash));
        CHECK(!holds_alternative<ValidationError>(verification2));
        REQUIRE(holds_alternative<ValidChain>(verification2));

        auto fcu_updated = exec_engine.notify_fork_choice_update(block_f1_hash, current_head_id.hash, {});
        CHECK(fcu_updated);

        auto new_head_id = exec_engine.last_finalized_block();
        CHECK(new_head_id.block_num == 9);
        auto new_progress = exec_engine.block_progress();
        CHECK(new_progress == 10);
        auto new_fork_choice = exec_engine.last_fork_choice();
        CHECK(new_fork_choice.block_num == 10);

        auto is_block1_canonical = exec_engine.is_canonical(block_f1_hash);
        CHECK(is_block1_canonical);
        auto is_block3_canonical = exec_engine.is_canonical(block_f2_hash);
        CHECK(!is_block3_canonical);
    }

    // Test scenario:
    //                  ↗  f1a (10) -> f1b (11) (fork 1)
    //  c7 -> c8 -> c9
    //                  ↘  f2a (10) -> f2b (11) (fork 2)  =>  fcu
    SECTION("creates and verifies two forks, chooses second") {
        auto block1a = generate_sample_child_blocks(current_head);
        block1a->header.difficulty = 17'171'480'576;  // a random value
        auto block1b = generate_sample_child_blocks(block1a->header);

        auto block2a = generate_sample_child_blocks(current_head);
        block2a->header.difficulty = 17'171'480'577;  // a random value
        auto block2b = generate_sample_child_blocks(block2a->header);

        auto blocks = std::vector<std::shared_ptr<Block>>{block1a, block1b, block2a, block2b};
        exec_engine.insert_blocks(blocks);

        auto block1a_hash = block1a->header.hash();
        auto block1b_hash = block1b->header.hash();
        auto block2a_hash = block2a->header.hash();
        auto block2b_hash = block2b->header.hash();

        auto verification1 = runner.run(exec_engine.verify_chain(block1b_hash));
        CHECK(!holds_alternative<ValidationError>(verification1));
        REQUIRE(holds_alternative<ValidChain>(verification1));

        auto verification2 = runner.run(exec_engine.verify_chain(block2b_hash));
        CHECK(!holds_alternative<ValidationError>(verification2));
        REQUIRE(holds_alternative<ValidChain>(verification2));

        auto fcu_updated = exec_engine.notify_fork_choice_update(block2b_hash, current_head_id.hash, {});
        CHECK(fcu_updated);

        auto new_head_id = exec_engine.last_finalized_block();
        CHECK(new_head_id.block_num == 9);
        auto new_progress = exec_engine.block_progress();
        CHECK(new_progress == 11);
        auto new_fork_choice = exec_engine.last_fork_choice();
        CHECK(new_fork_choice.block_num == 11);

        auto is_block1_canonical = exec_engine.is_canonical(block1a_hash);
        CHECK(!is_block1_canonical);
        auto is_block2_canonical = exec_engine.is_canonical(block1b_hash);
        CHECK(!is_block2_canonical);
        auto is_block3_canonical = exec_engine.is_canonical(block2a_hash);
        CHECK(is_block3_canonical);
        auto is_block4_canonical = exec_engine.is_canonical(block2b_hash);
        CHECK(is_block4_canonical);
    }

    // Test scenario:
    // c7 -> c8 -> c9 -> f1 -> f2
    SECTION("insert_blocks updates chain database") {
        auto block1 = generate_sample_child_blocks(current_head);
        auto block2 = generate_sample_child_blocks(block1->header);

        auto block1_hash = block1->header.hash();
        auto block2_hash = block2->header.hash();

        CHECK(!read_block_num(tx, block1_hash).has_value());
        CHECK(!read_block_num(tx, block2_hash).has_value());

        auto blocks = std::vector<std::shared_ptr<Block>>{block1, block2};
        exec_engine.insert_blocks(blocks);

        CHECK(read_block_num(tx, block1_hash).has_value());
        CHECK(read_block_num(tx, block2_hash).has_value());

        tx.commit_and_renew();  // exec_engine.insert_blocks() automatically commits every 1000 blocks
        exec_engine.close();

        auto tx2 = db_access.start_ro_tx();
        CHECK(read_block_num(tx2, block1_hash).has_value());
        CHECK(read_block_num(tx2, block2_hash).has_value());
    }

    SECTION("verify_chain updates chain database") {
        auto block1 = generate_sample_child_blocks(current_head);
        auto block2 = generate_sample_child_blocks(block1->header);

        auto block1_hash = block1->header.hash();
        auto block2_hash = block2->header.hash();

        CHECK(!read_block_num(tx, block1_hash).has_value());
        CHECK(!read_block_num(tx, block2_hash).has_value());

        auto blocks = std::vector<std::shared_ptr<Block>>{block1, block2};
        exec_engine.insert_blocks(blocks);
        runner.run(exec_engine.verify_chain(block2_hash));

        CHECK(read_block_num(tx, block1_hash).has_value());
        CHECK(read_block_num(tx, block2_hash).has_value());

        exec_engine.close();

        auto tx2 = db_access.start_ro_tx();

        CHECK(read_block_num(tx2, block1_hash).has_value());
        CHECK(read_block_num(tx2, block2_hash).has_value());
        tx2.abort();
    }

    SECTION("notify_fork_choice_update does not update chain database") {
        auto block1 = generate_sample_child_blocks(current_head);
        auto block2 = generate_sample_child_blocks(block1->header);

        auto block1_hash = block1->header.hash();
        auto block2_hash = block2->header.hash();

        CHECK(!read_block_num(tx, block1_hash).has_value());
        CHECK(!read_block_num(tx, block2_hash).has_value());

        auto blocks = std::vector<std::shared_ptr<Block>>{block1, block2};
        exec_engine.insert_blocks(blocks);
        runner.run(exec_engine.verify_chain(block2_hash));
        exec_engine.notify_fork_choice_update(block2_hash, current_head_id.hash, {});

        CHECK(read_block_num(tx, block1_hash).has_value());
        CHECK(read_block_num(tx, block2_hash).has_value());

        exec_engine.close();

        auto tx2 = db_access.start_ro_tx();
        CHECK(read_block_num(tx2, block1_hash).has_value());
        CHECK(read_block_num(tx2, block2_hash).has_value());
        tx2.abort();
    }

    // TODO: temporarily disabled, to be fixed (JG)
    // SECTION("updates storage") {
    //     static constexpr evmc::address kSender{0xb685342b8c54347aad148e1f22eff3eb3eb29391_address};
    //     auto block1 = generate_sample_child_blocks(current_head);

    //     // This contract initially sets its 0th storage to 0x2a and its 1st storage to 0x01c9.
    //     // When called, it updates its 0th storage to the input provided.
    //     Bytes contract_code{*from_hex("600035600055")};
    //     Bytes deployment_code{*from_hex("602a6000556101c960015560068060166000396000f3") + contract_code};
    //     block1->transactions.resize(1);
    //     block1->transactions[0].chain_id = node_settings.chain_config->chain_id;
    //     block1->transactions[0].data = deployment_code;
    //     block1->transactions[0].gas_limit = block1->header.gas_limit;
    //     block1->transactions[0].type = TransactionType::kDynamicFee;
    //     block1->transactions[0].max_priority_fee_per_gas = 0;
    //     block1->transactions[0].max_fee_per_gas = 20 * kGiga;
    //     block1->transactions[0].r = 1;  // dummy
    //     block1->transactions[0].s = 1;  // dummy
    //     block1->transactions[0].set_sender(kSender);
    //     // block1->transactions[0].

    //     auto block1_hash = block1->header.hash();

    //     auto block_inserted = exec_engine.insert_block(block1);
    //     REQUIRE(block_inserted);

    //     auto verification1 = exec_engine.verify_chain(block1_hash).get();
    //     REQUIRE(holds_alternative<ValidChain>(verification1));

    //     auto fcu_successful = exec_engine.notify_fork_choice_update(block1_hash, current_head_id.hash, {});
    //     REQUIRE(fcu_successful);

    //     auto contract_address{silkworm::create_address(kSender, /*nonce=*/0)};

    //     auto contract = read_account(tx, contract_address);
    //     REQUIRE(contract.has_value());

    //     evmc::bytes32 storage_key0{};
    //     auto storage_value0 = read_storage(tx, contract_address, silkworm::kDefaultIncarnation, storage_key0);
    //     CHECK(silkworm::to_hex(storage_value0) == "000000000000000000000000000000000000000000000000000000000000002a");

    //     evmc::bytes32 storage_key1{to_bytes32(*from_hex("01"))};
    //     auto storage_value1 = read_storage(tx, contract_address, silkworm::kDefaultIncarnation, storage_key1);
    //     CHECK(silkworm::to_hex(storage_value1) == "00000000000000000000000000000000000000000000000000000000000001c9");
    // }
}

TEST_CASE("ExecutionEngine") {
    TaskRunner runner;

    db::test_util::TempChainDataStore context;
    context.add_genesis_data();
    context.commit_txn();

    db::DataModelFactory data_model_factory = context.data_model_factory();

    Environment::set_stop_before_stage(stages::kSendersKey);  // only headers, block hashes and bodies

    NodeSettings node_settings = node::test_util::make_node_settings_from_temp_chain_data(context);

    ExecutionEngineForTest exec_engine{
        runner.executor(),
        node_settings,
        data_model_factory,
        /* log_timer_factory = */ std::nullopt,
        make_stages_factory(node_settings, data_model_factory),
        context.chaindata_rw(),
    };
    exec_engine.open();

    auto& tx = exec_engine.main_chain().tx();  // mdbx refuses to open a ROTxn when there is a RWTxn in the same thread

    auto header0_hash = read_canonical_header_hash(tx, 0);
    REQUIRE(header0_hash.has_value());

    auto header0 = read_canonical_header(tx, 0);
    REQUIRE(header0.has_value());

    BlockId block0_id{0, *header0_hash};

    // check db
    BlockBody block0_body;
    const bool block0_present = read_body(tx, *header0_hash, block0_id.block_num, block0_body);
    CHECK(block0_present);

    /* status:
     *         h0
     * input:
     *         h0 <----- h1
     */

    SECTION("one invalid body after the genesis") {
        auto block1 = std::make_shared<Block>();
        block1->header.number = 1;
        block1->header.difficulty = 17'171'480'576;  // a random value
        block1->header.parent_hash = *header0_hash;
        // auto header1_hash = block1.header.hash();
        block1->ommers.push_back(BlockHeader{});  // generate error InvalidOmmerHeader
        auto header1_hash = block1->header.hash();

        // getting initial status
        auto initial_progress = exec_engine.block_progress();
        CHECK(initial_progress == 0);
        auto last_fcu_at_start_time = exec_engine.last_fork_choice();
        CHECK(last_fcu_at_start_time == block0_id);

        // inserting headers & bodies
        exec_engine.insert_block(block1);

        // check db
        BlockBody saved_body;
        const bool block1_present = read_body(tx, header1_hash, block1->header.number, saved_body);
        CHECK(block1_present);

        auto progress = exec_engine.block_progress();
        CHECK(progress == 1);

        // verifying the chain
        auto verification = runner.run(exec_engine.verify_chain(header1_hash));

        CHECK(stages::read_stage_progress(tx, stages::kHeadersKey) == 1);
        CHECK(stages::read_stage_progress(tx, stages::kBlockHashesKey) == 1);
        CHECK(stages::read_stage_progress(tx, stages::kBlockBodiesKey) == 1);
        CHECK(stages::read_stage_progress(tx, stages::kSendersKey) == 0);
        CHECK(stages::read_stage_progress(tx, stages::kExecutionKey) == 0);

        CHECK(!holds_alternative<ValidationError>(verification));
        REQUIRE(holds_alternative<InvalidChain>(verification));
        auto invalid_chain = std::get<InvalidChain>(verification);

        CHECK(invalid_chain.unwind_point == BlockId{0, *header0_hash});
        CHECK(invalid_chain.bad_block.has_value());
        CHECK(invalid_chain.bad_block.value() == header1_hash);
        CHECK(invalid_chain.bad_headers.size() == 1);
        CHECK(*(invalid_chain.bad_headers.begin()) == header1_hash);

        // check status
        auto final_progress = exec_engine.block_progress();
        CHECK(final_progress == block1->header.number);
        CHECK(exec_engine.last_fork_choice() == last_fcu_at_start_time);  // not changed

        auto present_in_canonical = exec_engine.is_canonical(header1_hash);
        CHECK(!present_in_canonical);

        // reverting the chain
        bool updated = exec_engine.notify_fork_choice_update(*header0_hash, {}, {});
        CHECK(updated);

        CHECK(exec_engine.last_fork_choice() == last_fcu_at_start_time);  // not changed

        present_in_canonical = exec_engine.is_canonical(header1_hash);
        CHECK(!present_in_canonical);
    }

    SECTION("one valid body after the genesis") {
        std::string raw_header1 =
            "f90211a0d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3a01dcc4de8dec75d7aab85b567b6ccd41a"
            "d312451b948a7413f0a142fd40d493479405a56e2d52c817161883f50c441c3228cfe54d9fa0d67e4d450343046425ae4271474353"
            "857ab860dbc0a1dde64b41b5cd3a532bf3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e8"
            "1f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000008503ff80000001821388808455ba422499476574682f76312e302e302f"
            "6c696e75782f676f312e342e32a0969b900de27b6ac6a67742365dd65f55a0526c41fd18e1b16f1a1215c2e66f5988539bd4979fef"
            "1ec4";
        std::optional<Bytes> encoded_header1 = from_hex(raw_header1);

        auto block1 = std::make_shared<Block>();
        ByteView encoded_view = encoded_header1.value();
        auto decoding_result = rlp::decode(encoded_view, block1->header);
        // Note: block1 has zero transactions and zero ommers on mainnet
        REQUIRE(decoding_result);
        auto block1_hash = block1->header.hash();
        BlockId block1_id{1, block1_hash};

        // getting initial status
        auto initial_progress = exec_engine.block_progress();
        CHECK(initial_progress == 0);
        auto last_fcu_at_start_time = exec_engine.last_fork_choice();
        CHECK(last_fcu_at_start_time == block0_id);

        // inserting & verifying the block
        exec_engine.insert_block(block1);
        auto verification = runner.run(exec_engine.verify_chain(block1_hash));

        REQUIRE(holds_alternative<ValidChain>(verification));
        auto valid_chain = std::get<ValidChain>(verification);
        CHECK(valid_chain.current_head == block1_id);

        // check status
        auto final_progress = exec_engine.block_progress();
        CHECK(final_progress == block1->header.number);
        CHECK(exec_engine.last_fork_choice() == last_fcu_at_start_time);  // not changed

        // check db content
        BlockBody saved_body;
        bool present = read_body(tx, block1_hash, block1->header.number, saved_body);
        CHECK(present);

        auto present_in_canonical = exec_engine.is_canonical(block1_hash);
        CHECK(!present_in_canonical);  // the current head is not yet accepted

        // confirming the chain
        exec_engine.notify_fork_choice_update(block1_hash, header0_hash, {});

        // checking the status
        CHECK(exec_engine.last_fork_choice() == block1_id);
        CHECK(exec_engine.last_finalized_block() == block0_id);

        present_in_canonical = exec_engine.is_canonical(block1_hash);
        CHECK(present_in_canonical);
    }

    SECTION("a block that creates a fork") {
        auto block1 = generate_sample_child_blocks(*header0);
        auto block1_hash = block1->header.hash();

        auto block2 = generate_sample_child_blocks(block1->header);
        auto block2_hash = block2->header.hash();

        auto block3 = generate_sample_child_blocks(block2->header);
        auto block3_hash = block3->header.hash();

        // inserting & verifying the block
        exec_engine.insert_block(block1);
        exec_engine.insert_block(block2);
        exec_engine.insert_block(block3);
        auto verification = runner.run(exec_engine.verify_chain(block3_hash));

        REQUIRE(holds_alternative<ValidChain>(verification));
        auto valid_chain = std::get<ValidChain>(verification);
        CHECK(valid_chain.current_head == BlockId{3, block3_hash});

        // confirming the chain
        auto fcu_updated = exec_engine.notify_fork_choice_update(block3_hash, block1_hash, {});
        CHECK(fcu_updated);

        CHECK(exec_engine.last_fork_choice() == BlockId{3, block3_hash});
        CHECK(exec_engine.last_finalized_block() == BlockId{1, block1_hash});

        CHECK(exec_engine.get_canonical_hash(2) == block2_hash);
        CHECK(exec_engine.get_canonical_header(2).has_value());
        CHECK(exec_engine.get_canonical_hash(3) == block3_hash);
        CHECK(exec_engine.get_canonical_header(3).has_value());

        auto [head_block_num, head_hash] = read_canonical_head(tx);
        CHECK(head_block_num == 3);
        CHECK(head_hash == block3_hash);

        // creating and reintegrating a fork
        auto block4 = generate_sample_child_blocks(block3->header);
        auto block4_hash = block4->header.hash();
        {
            // inserting & verifying the block
            exec_engine.insert_block(block4);
            verification = runner.run(exec_engine.verify_chain(block4_hash));

            REQUIRE(holds_alternative<ValidChain>(verification));
            valid_chain = std::get<ValidChain>(verification);
            CHECK(valid_chain.current_head == BlockId{4, block4_hash});

            // confirming the chain (i.e. flushing the memory mutation on the main db)
            fcu_updated = exec_engine.notify_fork_choice_update(block4_hash, block1_hash, {});
            CHECK(fcu_updated);

            CHECK(exec_engine.last_fork_choice() == BlockId{4, block4_hash});
            CHECK(exec_engine.last_finalized_block() == BlockId{1, block1_hash});

            CHECK(exec_engine.get_canonical_hash(2) == block2_hash);
            CHECK(exec_engine.get_canonical_header(2).has_value());
            CHECK(exec_engine.get_canonical_hash(3) == block3_hash);
            CHECK(exec_engine.get_canonical_header(3).has_value());
            CHECK(exec_engine.get_canonical_hash(4) == block4_hash);
            CHECK(exec_engine.get_canonical_header(4).has_value());

            std::tie(head_block_num, head_hash) = read_canonical_head(tx);
            CHECK(head_block_num == 4);
            CHECK(head_hash == block4_hash);
        }

        // creating a fork and changing the head (trigger unwind)
        auto block2b = generate_sample_child_blocks(block1->header);
        block2b->header.extra_data = string_view_to_byte_view("I'm different");  // to make it different from block2
        auto block2b_hash = block2b->header.hash();
        {
            // inserting & verifying the block
            exec_engine.insert_block(block2b);
            verification = runner.run(exec_engine.verify_chain(block2b_hash));

            REQUIRE(holds_alternative<ValidChain>(verification));
            valid_chain = std::get<ValidChain>(verification);
            CHECK(valid_chain.current_head == BlockId{2, block2b_hash});

            // confirming the chain
            fcu_updated = exec_engine.notify_fork_choice_update(block2b_hash, header0_hash, {});
            CHECK(fcu_updated);

            CHECK(exec_engine.last_fork_choice() == BlockId{2, block2b_hash});
            CHECK(exec_engine.last_finalized_block() == block0_id);
            CHECK(exec_engine.main_chain().last_chosen_head() == BlockId{2, block2b_hash});

            CHECK(exec_engine.get_canonical_hash(2) == block2b_hash);
            CHECK(exec_engine.get_canonical_header(2).has_value());
            CHECK_FALSE(exec_engine.get_canonical_header(3).has_value());
            CHECK_FALSE(exec_engine.get_canonical_header(4).has_value());

            std::tie(head_block_num, head_hash) = read_canonical_head(tx);
            CHECK(head_block_num == 2);
            CHECK(head_hash == block2b_hash);
        }

        CHECK(exec_engine.get_header(block2b_hash).has_value());  // we do not remove old blocks
        CHECK(exec_engine.get_header(block2_hash).has_value());   // we do not remove old blocks
        CHECK(exec_engine.get_header(block3_hash).has_value());   // we do not remove old blocks
        CHECK(exec_engine.get_header(block4_hash).has_value());   // we do not remove old blocks
    }
}

}  // namespace silkworm
