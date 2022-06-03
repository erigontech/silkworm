/*
   Copyright 2021-2022 The Silkworm Authors

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

#ifndef SILKWORM_COMMON_ASSERT_HPP_
#define SILKWORM_COMMON_ASSERT_HPP_

#include <silkworm/common/optimization.h>

namespace silkworm {
void abort_due_to_assertion_failure(char const* expr, char const* file, long line);
}

// SILKWORM_ASSERT always aborts program execution on assertion failure, even when NDEBUG is defined.
#define SILKWORM_ASSERT(expr)                             \
    (SILKWORM_PREDICT_TRUE((expr)) ? static_cast<void>(0) \
                                   : ::silkworm::abort_due_to_assertion_failure(#expr, __FILE__, __LINE__))

#endif  // SILKWORM_COMMON_ASSERT_HPP_
