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

#include <cstdint>

namespace silkworm::snapshots {

//! The snapshot category corresponding to the snapshot file type
//! @remark item names do NOT follow Google style to obtain the tag used in file names from magic_enum::enum_name
//! @see SnapshotPath#build_filename
// NOLINTBEGIN(readability-identifier-naming)
enum SnapshotType : uint8_t {
    headers = 0,
    bodies = 1,
    transactions = 2,
    transactions_to_block = 3,
};
// NOLINTEND(readability-identifier-naming)

}  // namespace silkworm::snapshots
