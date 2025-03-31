// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "stage_triggers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/infra/concurrency/spawn.hpp>

namespace silkworm::stagedsync {

using namespace silkworm::db;
using db::test_util::TempChainDataStore;

class TriggersStateForTest : public TriggersStage {
  public:
    using TriggersStage::TriggersStage;
    boost::asio::io_context& io_context() { return ioc_; }
};

TEST_CASE("TriggersStage: scheduled task lifetime") {
    TempChainDataStore temp_chaindata;
    RWTxn& txn{temp_chaindata.rw_txn()};
    txn.disable_commit();

    stagedsync::SyncContext sync_context{};
    TriggersStateForTest stage_triggers{&sync_context};
    auto future = concurrency::spawn_future(stage_triggers.io_context(), stage_triggers.schedule([](auto& rw_txn) {
        rw_txn.is_open();
    }));
    REQUIRE(stage_triggers.forward(txn) == stagedsync::Stage::Result::kSuccess);
    CHECK_NOTHROW(future.get());
}

}  // namespace silkworm::stagedsync
