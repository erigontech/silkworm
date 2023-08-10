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

#include "compatibility.hpp"

namespace silkworm::rpc::compatibility {

//! Flag indicating if strict compatibility with Erigon RpcDaemon at JSON RPC level is guaranteed
static bool erigon_json_strict_compatibility_required{false};

bool is_erigon_json_api_compatibility_required() {
    return erigon_json_strict_compatibility_required;
}

void set_erigon_json_api_compatibility_required(bool compatibility_required) {
    erigon_json_strict_compatibility_required = compatibility_required;
}

}  // namespace silkworm::rpc::compatibility
