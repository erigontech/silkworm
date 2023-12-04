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
