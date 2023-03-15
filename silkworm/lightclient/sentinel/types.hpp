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

#include <string>

#include <silkworm/core/common/base.hpp>
#include <silkworm/lightclient/util/hash32.hpp>

namespace silkworm::cl::sentinel {

struct Status {
    uint32_t fork_digest{0};
    Hash32 finalized_root;
    uint64_t finalized_epoch{0};
    Hash32 head_root;
    uint64_t head_slot{0};
};

struct RequestData {
    Bytes data;  // SSZ encoded
    std::string topic;
};

struct ResponseData {
    Bytes data;  // SSZ encoded
    bool error{false};
};

}  // namespace silkworm::cl::sentinel
