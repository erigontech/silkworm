/*
   Copyright 2022 The Silkworm Authors

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

#include "index.hpp"

#include <utility>

#include <catch2/catch.hpp>

#include <silkworm/test/log.hpp>
#include <silkworm/test/snapshot_files.hpp>

namespace silkworm {

TEST_CASE("Index::Index", "[silkworm][snapshot][index]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    test::TemporarySnapshotFile tmp_snapshot_file{"v1-014500-015000-headers.seg"};
    HeaderIndex header_index{*SnapshotFile::parse(tmp_snapshot_file.path().string())};
    CHECK_THROWS_AS(header_index.build(), std::logic_error);
}

}  // namespace silkworm
