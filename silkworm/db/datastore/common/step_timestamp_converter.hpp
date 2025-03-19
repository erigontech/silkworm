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

#include "step.hpp"
#include "timestamp.hpp"

namespace silkworm::datastore {

struct StepToTimestampConverter {
    size_t step_size;

    Step step_from_timestamp(Timestamp t) const;
    Timestamp timestamp_from_step(Step s) const;

    StepRange step_range_from_timestamp_range(TimestampRange range) const;
    TimestampRange timestamp_range_from_step_range(StepRange range) const {
        return TimestampRange{timestamp_from_step(range.start), timestamp_from_step(range.end)};
    }
};

}  // namespace silkworm::datastore
