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

#include <silkworm/db/datastore/common/step_timestamp_converter.hpp>

namespace silkworm::db::blocks {

//! Scale factor to convert from-to block number values in block snapshot file names
inline constexpr size_t kStepSizeForBlockSnapshots = 1'000;

inline constexpr datastore::StepToTimestampConverter kStepToBlockNumConverter{kStepSizeForBlockSnapshots};

}  // namespace silkworm::db::blocks
