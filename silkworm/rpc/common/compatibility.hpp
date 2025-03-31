// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

namespace silkworm::rpc::compatibility {

bool is_erigon_json_api_compatibility_required();
void set_erigon_json_api_compatibility_required(bool compatibility_required);

}  // namespace silkworm::rpc::compatibility
