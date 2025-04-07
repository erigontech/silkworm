// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "issuance.hpp"

#include <sstream>

namespace silkworm::rpc {

std::ostream& operator<<(std::ostream& out, const Issuance& issuance) {
    out << issuance.to_string();
    return out;
}

std::string Issuance::to_string() const {
    std::stringstream out;
    out << "block_reward: " << block_reward.value_or("null") << " "
        << "ommer_reward: " << ommer_reward.value_or("null") << " "
        << "issuance: " << issuance.value_or("null") << " ";
    return out.str();
}

}  // namespace silkworm::rpc
