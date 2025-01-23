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

#include <functional>
#include <stdexcept>
#include <string>

namespace silkworm {

//! Ensure that condition is met, otherwise raise a logic error with string literal message
template <unsigned int N>
inline void ensure(bool condition, const char (&message)[N]) {
    if (!condition) [[unlikely]] {
        throw std::logic_error(message);
    }
}

//! Ensure that condition is met, otherwise raise a logic error with dynamically built message
//! Usage: `ensure(condition, [&]() { return "Message: " + get_str(); });`
inline void ensure(bool condition, const std::function<std::string()>& message_builder) {
    if (!condition) [[unlikely]] {
        throw std::logic_error(message_builder());
    }
}

//! Similar to \code ensure with emphasis on invariant violation
template <unsigned int N>
inline void ensure_invariant(bool condition, const char (&message)[N]) {
    if (!condition) [[unlikely]] {
        throw std::logic_error("Invariant violation: " + std::string{message});
    }
}

//! Similar to \code ensure with emphasis on invariant violation
inline void ensure_invariant(bool condition, const std::function<std::string()>& message_builder) {
    if (!condition) [[unlikely]] {
        throw std::logic_error("Invariant violation: " + message_builder());
    }
}

//! Similar to \code ensure with emphasis on pre-condition violation
inline void ensure_pre_condition(bool condition, const std::function<std::string()>& message_builder) {
    if (!condition) [[unlikely]] {
        throw std::invalid_argument("Pre-condition violation: " + message_builder());
    }
}

//! Similar to \code ensure with emphasis on post-condition violation
inline void ensure_post_condition(bool condition, const std::function<std::string()>& message_builder) {
    if (!condition) [[unlikely]] {
        throw std::logic_error("Post-condition violation: " + message_builder());
    }
}

}  // namespace silkworm
