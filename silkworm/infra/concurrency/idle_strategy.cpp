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

#include "idle_strategy.hpp"

#include <absl/strings/str_cat.h>

namespace silkworm::concurrency {

bool AbslParseFlag(absl::string_view text, WaitMode* wait_mode, std::string* error) {
    if (text == "backoff") {
        *wait_mode = WaitMode::kBackoff;
        return true;
    }
    if (text == "blocking") {
        *wait_mode = WaitMode::kBlocking;
        return true;
    }
    if (text == "sleeping") {
        *wait_mode = WaitMode::kSleeping;
        return true;
    }
    if (text == "yielding") {
        *wait_mode = WaitMode::kYielding;
        return true;
    }
    if (text == "busy_spin") {
        *wait_mode = WaitMode::kBusySpin;
        return true;
    }
    *error = "unknown value for WaitMode";
    return false;
}

std::string AbslUnparseFlag(WaitMode wait_mode) {
    switch (wait_mode) {
        case WaitMode::kBackoff:
            return "backoff";
        case WaitMode::kBlocking:
            return "blocking";
        case WaitMode::kSleeping:
            return "sleeping";
        case WaitMode::kYielding:
            return "yielding";
        case WaitMode::kBusySpin:
            return "busy_spin";
        default:
            return absl::StrCat(wait_mode);
    }
}

}  // namespace silkworm::concurrency
