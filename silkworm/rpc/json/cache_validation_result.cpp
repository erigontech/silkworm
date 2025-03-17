/*
   Copyright 2025 The Silkworm Authors

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

#include "cache_validation_result.hpp"

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const CacheValidationResult& result) {
    json["requestCanceled"] = result.ref.request_canceled;
    json["enabled"] = result.ref.enabled;
    json["latestStateBehind"] = result.ref.latest_state_behind;
    json["cacheCleared"] = result.ref.cache_cleared;
    json["latestStateID"] = result.ref.latest_state_version_id;
    json["stateKeysOutOfSync"] = result.ref.state_keys_out_of_sync;
    json["codeKeysOutOfSync"] = result.ref.code_keys_out_of_sync;
}

}  // namespace silkworm::rpc
