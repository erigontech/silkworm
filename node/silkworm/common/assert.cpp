/*
   Copyright 2021 The Silkworm Authors

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

#include "assert.hpp"

#include <cstdlib>

#include "log.hpp"

namespace silkworm {
void abort_due_to_assertion_failure(char const* expr, char const* file, long line) {
    SILKWORM_LOG(LogLevel::Critical) << "Assert failed: " << expr << "\n"
                                     << "Source: " << file << ", line " << line << "\n";
    std::abort();
}
}  // namespace silkworm
