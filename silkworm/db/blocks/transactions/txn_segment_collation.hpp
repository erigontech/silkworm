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

#include <silkworm/db/datastore/segment_collation.hpp>

namespace silkworm::db {

class TransactionSegmentCollation : public datastore::SegmentCollation {
  public:
    ~TransactionSegmentCollation() override = default;
    void copy(datastore::kvdb::ROTxn& txn, const datastore::SegmentCollationCommand& command, snapshots::segment::SegmentFileWriter& file_writer) const override;
    void prune(datastore::kvdb::RWTxn& txn, BlockNumRange range) const override;
};

}  // namespace silkworm::db
