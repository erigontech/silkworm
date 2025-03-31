// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <string>

namespace silkworm {

//! Generate a new JSON Web Token (JWT) secret
std::string generate_jwt_token(const std::filesystem::path& file_path);

//! Load a JWT secret token from provided file path. If the file doesn't contain the token then we generate one
std::string load_jwt_token(const std::filesystem::path& file_path);

}  // namespace silkworm
