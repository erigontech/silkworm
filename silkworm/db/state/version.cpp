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

#include "version.hpp"

namespace silkworm::db::state {

//! Flag indicating if version of Erigon data format for state is V3 or not
static bool data_format_v3{false};

void set_data_format_v3(bool is_data_format_v3) {
    data_format_v3 = is_data_format_v3;
}

bool is_data_format_v3() {
    return data_format_v3;
}

}  // namespace silkworm::db::state
