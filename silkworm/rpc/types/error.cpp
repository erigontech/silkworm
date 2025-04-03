// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "error.hpp"

#include <iomanip>
#include <sstream>

#include <silkworm/core/common/util.hpp>

namespace silkworm::rpc {

std::ostream& operator<<(std::ostream& out, const Error& error) {
    out << error.to_string();
    return out;
}

std::string Error::to_string() const {
    const auto& error = *this;
    std::stringstream out;

    out << " code: " << error.code << " message: " << error.message;
    return out.str();
}

std::ostream& operator<<(std::ostream& out, const RevertError& error) {
    out << error.to_string();
    return out;
}

std::string RevertError::to_string() const {
    const auto& error = *this;
    std::stringstream out;

    out << " code: " << error.code << " message: " << error.message << " data: " << silkworm::to_hex(error.data);
    return out.str();
}

}  // namespace silkworm::rpc
