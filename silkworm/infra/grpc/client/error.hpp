// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>
#include <system_error>

std::error_code make_error_code(int error_code, std::string error_message);
