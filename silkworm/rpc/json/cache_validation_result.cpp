// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
