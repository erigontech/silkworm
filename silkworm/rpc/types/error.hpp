// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <iostream>
#include <string>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::rpc {

struct Error {
    int code{0};
    std::string message;
};

std::ostream& operator<<(std::ostream& out, const Error& error);

struct RevertError : public Error {
    silkworm::Bytes data;
};

std::ostream& operator<<(std::ostream& out, const RevertError& error);

}  // namespace silkworm::rpc
