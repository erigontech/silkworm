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

#pragma once

#include <silkworm/core/common/base.hpp>
#include <silkworm/db/datastore/common/step.hpp>
#include <silkworm/db/datastore/common/step_timestamp_converter.hpp>

namespace silkworm::db::state {

//! Scale factor to convert from-to txn id values in temporal snapshot file names
inline constexpr size_t kStepSizeForTemporalSnapshots = 1'562'500;  // = 100M / 64

inline constexpr datastore::StepToTimestampConverter kStepToTxnIdConverter{kStepSizeForTemporalSnapshots};

}  // namespace silkworm::db::state
