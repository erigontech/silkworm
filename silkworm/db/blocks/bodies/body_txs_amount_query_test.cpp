// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "body_txs_amount_query.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/blocks/step_block_num_converter.hpp>
#include <silkworm/db/test_util/temp_snapshots.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::snapshots {

TEST_CASE("BodyTxsAmountSegmentQuery") {
    TemporaryDirectory tmp_dir;
    test_util::SampleBodySnapshotFile snapshot_file{tmp_dir.path()};
    segment::SegmentFileReader snapshot{snapshot_file.path(), db::blocks::kStepToBlockNumConverter};

    BodyTxsAmountSegmentQuery query{snapshot};
    auto result = query.exec();

    CHECK(result.first_tx_id == 7'341'262);
    CHECK(result.count == 12);
}

}  // namespace silkworm::snapshots
