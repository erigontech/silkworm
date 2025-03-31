// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "error.hpp"

#include <iomanip>

#include <silkworm/core/common/util.hpp>

namespace silkworm::rpc {

std::ostream& operator<<(std::ostream& out, const Error& error) {
    out << " code: " << error.code << " message: " << error.message;
    return out;
}

std::ostream& operator<<(std::ostream& out, const RevertError& error) {
    out << " code: " << error.code << " message: " << error.message << " data: " << silkworm::to_hex(error.data);
    return out;
}

}  // namespace silkworm::rpc
