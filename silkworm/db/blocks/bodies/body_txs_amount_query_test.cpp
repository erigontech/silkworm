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

#include "body_txs_amount_query.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/test_util/temp_snapshots.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::snapshots {

TEST_CASE("BodyTxsAmountQuery") {
    silkworm::test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    TemporaryDirectory tmp_dir;
    test_util::SampleBodySnapshotFile snapshot_file{tmp_dir.path()};
    SegmentFileReader snapshot{snapshot_file.path()};
    snapshot.reopen_segment();

    BodyTxsAmountQuery query{snapshot};
    auto result = query.exec();

    CHECK(result.first_tx_id == 7'341'262);
    CHECK(result.count == 12);
}

}  // namespace silkworm::snapshots
