// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc {

struct CallBundleTxInfo {
    ethash_hash256 hash;
    uint64_t gas_used;
    evmc::bytes32 value;
    std::string error_message;
};

struct CallBundleInfo {
    ethash_hash256 bundle_hash;
    std::vector<CallBundleTxInfo> txs_info;
};

}  // namespace silkworm::rpc
