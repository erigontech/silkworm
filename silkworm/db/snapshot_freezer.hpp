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

#pragma once

#include <silkworm/core/common/base.hpp>

#include "mdbx/mdbx.hpp"
#include "snapshots/snapshot_writer.hpp"

namespace silkworm::db {

struct SnapshotFreezer {
    virtual ~SnapshotFreezer() = default;

    //! Copies data for a block range from db to the snapshot file.
    virtual void copy(ROTxn& txn, BlockNumRange range, snapshots::SnapshotFileWriter& file_writer) const = 0;
};

}  // namespace silkworm::db
