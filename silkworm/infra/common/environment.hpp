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

#include <silkworm/core/common/base.hpp>

namespace silkworm {

class Environment {
  public:
    static std::optional<BlockNum> get_stop_at_block();
    static void set_stop_at_block(BlockNum block_num);

    static std::optional<std::string> get_start_at_stage();
    static void set_start_at_stage(const std::string& stage_name);

    static std::optional<std::string> get_stop_before_stage();
    static void set_stop_before_stage(const std::string& stage_name);

    static bool are_pre_verified_hashes_disabled();
    static void set_pre_verified_hashes_disabled();
};

}  // namespace silkworm