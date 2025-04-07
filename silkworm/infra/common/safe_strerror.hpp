// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

namespace silkworm {

//! \brief Converts a system error code into its message.
//! \remarks Thread-safe version of strerror.
std::string safe_strerror(int err_code);

}  // namespace silkworm
