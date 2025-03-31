// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "issuance.hpp"

namespace silkworm::rpc {

std::ostream& operator<<(std::ostream& out, const Issuance& issuance) {
    out << "block_reward: " << issuance.block_reward.value_or("null") << " "
        << "ommer_reward: " << issuance.ommer_reward.value_or("null") << " "
        << "issuance: " << issuance.issuance.value_or("null") << " ";
    return out;
}

}  // namespace silkworm::rpc
