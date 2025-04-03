// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "call_bundle.hpp"

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const struct CallBundleTxInfo& tx_info) {
    json["gasUsed"] = tx_info.gas_used;
    json["txHash"] = silkworm::to_bytes32({tx_info.hash.bytes, silkworm::kHashLength});
    if (!tx_info.error_message.empty())
        json["error"] = tx_info.error_message;
    else
        json["value"] = silkworm::to_bytes32({tx_info.value.bytes, silkworm::kHashLength});
}

void to_json(nlohmann::json& json, const struct CallBundleInfo& bundle_info) {
    json["bundleHash"] = silkworm::to_bytes32({bundle_info.bundle_hash.bytes, silkworm::kHashLength});
    json["results"] = bundle_info.txs_info;
}

}  // namespace silkworm::rpc
