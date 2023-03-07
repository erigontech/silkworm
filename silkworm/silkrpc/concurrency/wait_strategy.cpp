/*
   Copyright 2020 The Silkrpc Authors

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

#include "wait_strategy.hpp"

#include <utility>

#include <absl/strings/str_cat.h>

namespace silkrpc {

bool AbslParseFlag(absl::string_view text, WaitMode* wait_mode, std::string* error) {
    if (text == "backoff") {
        *wait_mode = WaitMode::backoff;
        return true;
    }
    if (text == "blocking") {
        *wait_mode = WaitMode::blocking;
        return true;
    }
    if (text == "sleeping") {
        *wait_mode = WaitMode::sleeping;
        return true;
    }
    if (text == "yielding") {
        *wait_mode = WaitMode::yielding;
        return true;
    }
    if (text == "spin_wait") {
        *wait_mode = WaitMode::spin_wait;
        return true;
    }
    if (text == "busy_spin") {
        *wait_mode = WaitMode::busy_spin;
        return true;
    }
    *error = "unknown value for WaitMode";
    return false;
}

std::string AbslUnparseFlag(WaitMode wait_mode) {
    switch (wait_mode) {
        case WaitMode::backoff: return "backoff";
        case WaitMode::blocking: return "blocking";
        case WaitMode::sleeping: return "sleeping";
        case WaitMode::yielding: return "yielding";
        case WaitMode::spin_wait: return "spin_wait";
        case WaitMode::busy_spin: return "busy_spin";
        default: return absl::StrCat(wait_mode);
    }
}

} // namespace silkrpc
