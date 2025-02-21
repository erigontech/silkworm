/*
   Copyright 2025 The Silkworm Authors

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

#include "step.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm::datastore {

TEST_CASE("Step", "[datastore][common]") {
    CHECK(Step{0}.to_block_num() == 0);
    CHECK(Step{500}.to_block_num() == 500'000);

    CHECK(Step{0}.to_txn_id() == 0);
    CHECK(Step{64}.to_txn_id() == 100'000'000);

    SECTION("Step constructor and value") {
        Step step{10};
        CHECK(step.value == 10);
    }

    SECTION("Step comparison operators") {
        Step step1{10};
        Step step2{20};

        CHECK(step1 < step2);
        CHECK(step1 <= step2);
        CHECK_FALSE(step2 < step1);
    }

    SECTION("Step to string") {
        Step step{100};
        CHECK(step.to_string() == "100st");
    }

    SECTION("Step to BlockNum and back") {
        Step step{10};
        BlockNum block_num = step.to_block_num();
        CHECK(block_num == 10'000);  // 10 * 1000 = 10000
        CHECK(Step::from_block_num(block_num).value == 10);
    }

    SECTION("Step to TxnId and back") {
        Step step{10};
        TxnId txn_id = step.to_txn_id();
        CHECK(txn_id == 15'625'000);  // 10 * 1562500 = 15625000
        CHECK(Step::from_txn_id(txn_id).value == 10);
    }

    SECTION("Step limits") {
        CHECK(Step::from_block_num(kMaxBlockNum).value == kMaxBlockNum / kStepSizeForBlockSnapshots);
        CHECK(Step::from_txn_id(kMaxTxnId).value == kMaxTxnId / kStepSizeForTemporalSnapshots);
    }
}

TEST_CASE("StepRange", "[datastore][common]") {
    CHECK(StepRange{Step{0}, Step{0}}.to_block_num_range() == BlockNumRange{0, 0});
    CHECK(StepRange{Step{0}, Step{500}}.to_block_num_range() == BlockNumRange{0, 500'000});

    StepRange range(Step{10}, Step{20});

    SECTION("StepRange constructor and containment") {
        CHECK(range.start.value == 10);
        CHECK(range.end.value == 20);
        CHECK(range.contains(Step{15}));
        CHECK_FALSE(range.contains(Step{25}));
    }

    SECTION("StepRange size") {
        CHECK(range.size() == 10);
    }

    SECTION("StepRange to string") {
        CHECK(range.to_string() == "[10st, 20st)");
    }

    SECTION("StepRange to BlockNumRange and back") {
        const BlockNumRange block_range = range.to_block_num_range();
        CHECK(block_range.start == 10000);
        CHECK(block_range.end == 20000);

        const StepRange step_range = StepRange::from_block_num_range(block_range);
        CHECK(step_range.start.value == 10);
        CHECK(step_range.end.value == 20);
    }

    SECTION("StepRange to TxnIdRange and back") {
        const TxnIdRange txn_range = range.to_txn_id_range();
        CHECK(txn_range.start == 15625000);
        CHECK(txn_range.end == 31250000);

        const StepRange restored_range = StepRange::from_txn_id_range(txn_range);
        CHECK(restored_range.start.value == 10);
        CHECK(restored_range.end.value == 20);
    }

    SECTION("StepRange limits") {
        const StepRange r1 = StepRange::from_block_num_range(BlockNumRange{0, kMaxBlockNum - kStepSizeForBlockSnapshots + 2});
        CHECK(r1.end.value == kMaxBlockNum / kStepSizeForBlockSnapshots);

        const StepRange r2 = StepRange::from_txn_id_range(TxnIdRange{0, kMaxTxnId - kStepSizeForTemporalSnapshots + 2});
        CHECK(r2.end.value == kMaxTxnId / kStepSizeForTemporalSnapshots);

        const StepRange r3 = StepRange::from_block_num_range(BlockNumRange{kMaxBlockNum, kMaxBlockNum});
        CHECK(r3.start.value == kMaxBlockNum / kStepSizeForBlockSnapshots);
        CHECK(r3.end.value == kMaxBlockNum / kStepSizeForBlockSnapshots);

        const StepRange r4 = StepRange::from_txn_id_range(TxnIdRange{kMaxTxnId, kMaxTxnId});
        CHECK(r4.start.value == kMaxTxnId / kStepSizeForTemporalSnapshots);
        CHECK(r4.end.value == kMaxTxnId / kStepSizeForTemporalSnapshots);
    }
}

}  // namespace silkworm::datastore
