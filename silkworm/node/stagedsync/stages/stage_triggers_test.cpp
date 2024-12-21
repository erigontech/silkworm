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
