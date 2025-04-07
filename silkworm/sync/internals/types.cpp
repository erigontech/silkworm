// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "types.hpp"

#include <magic_enum.hpp>

namespace silkworm {

std::ostream& operator<<(std::ostream& os, const PeerPenalization& penalization) {
    os << penalization.to_string();
    return os;
}

std::string PeerPenalization::to_string() const {
    const auto& penalization = *this;
    std::stringstream os;

    os << "peer_id=" << penalization.peer_id << " cause=" << magic_enum::enum_name(penalization.penalty);
    return os.str();
}

}  // namespace silkworm
