// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <iostream>
#include <optional>
#include <string>

namespace silkworm::rpc {

struct Issuance {
    std::optional<std::string> block_reward;
    std::optional<std::string> ommer_reward;
    std::optional<std::string> issuance;
    std::optional<std::string> burnt;
    std::optional<std::string> total_issued;
    std::optional<std::string> total_burnt;
    std::optional<std::string> tips;

    std::string to_string() const;
};

std::ostream& operator<<(std::ostream& out, const Issuance& issuance);

}  // namespace silkworm::rpc
