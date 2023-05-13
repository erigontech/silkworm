/*
   Copyright 2023 The Silkworm Authors

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

#include <stdexcept>
#include <string>

namespace silkworm {

//! Ensure that condition is met, otherwise raise a logic error with specified message
inline void ensure(bool condition, const std::string& message) {
    if (!condition) {
        throw std::logic_error(message);
    }
}

//! Similar to \code ensure with emphasis on invariant violation
inline void ensure_invariant(bool condition, const std::string& message) {
    ensure(condition, "Invariant violation: " + message);
}

}  // namespace silkworm
