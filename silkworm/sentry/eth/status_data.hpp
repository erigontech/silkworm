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

#pragma once

#include <vector>

#include <silkworm/core/common/base.hpp>

#include "status_message.hpp"

namespace silkworm::sentry::eth {

struct StatusData {
    std::vector<BlockNum> fork_block_numbers;
    std::vector<BlockTime> fork_block_times;
    BlockNum head_block_num{0};
    StatusMessage message;
};

}  // namespace silkworm::sentry::eth
