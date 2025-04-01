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

#include <sstream>

#include <silkworm/core/common/base.hpp>

#include "data_migration_command.hpp"
#include "kvdb/mdbx.hpp"
#include "snapshots/segment/segment_writer.hpp"

namespace silkworm::datastore {

struct SegmentCollationCommand : public DataMigrationCommand {
    BlockNumRange range;
    uint64_t base_txn_id;

    SegmentCollationCommand(BlockNumRange range1, uint64_t base_txn_id1)
        : range(range1),
          base_txn_id(base_txn_id1) {}
    ~SegmentCollationCommand() override = default;

    std::string to_string() const override {
        std::stringstream stream;
        stream << "SegmentCollationCommand " << range.to_string();
        return stream.str();
    }
};

struct SegmentCollation {
    virtual ~SegmentCollation() = default;

    //! Copies data for a block range from db to the snapshot file.
    virtual void copy(datastore::kvdb::ROTxn& txn, const SegmentCollationCommand& command, snapshots::segment::SegmentFileWriter& file_writer) const = 0;

    //! Cleans up data for a block range from db after it was copied to the snapshot file.
    virtual void prune(datastore::kvdb::RWTxn& txn, BlockNumRange range) const = 0;
};

}  // namespace silkworm::datastore
