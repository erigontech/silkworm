// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
