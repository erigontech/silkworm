// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/datastore/segment_collation.hpp>

namespace silkworm::db {

class BodySegmentCollation : public datastore::SegmentCollation {
  public:
    ~BodySegmentCollation() override = default;
    void copy(datastore::kvdb::ROTxn& txn, const datastore::SegmentCollationCommand& command, snapshots::segment::SegmentFileWriter& file_writer) const override;
    void prune(datastore::kvdb::RWTxn& txn, BlockNumRange range) const override;
};

}  // namespace silkworm::db
