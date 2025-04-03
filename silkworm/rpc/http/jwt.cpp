// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "jwt.hpp"

#include <filesystem>
#include <fstream>
#include <string>

#include <silkworm/core/common/random_number.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/log.hpp>

static std::string hex_to_string(const std::string& jwt_token) {
    const auto jwt_token_bytes = silkworm::from_hex(jwt_token);
    if (!jwt_token_bytes) {
        const auto error_msg{"JWT token format is incorrect: " + jwt_token};
        SILK_ERROR << error_msg;
        throw std::runtime_error{error_msg};
    }

    return {jwt_token_bytes->cbegin(), jwt_token_bytes->cend()};
}

namespace silkworm {

static constexpr char kHexCharacters[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

static constexpr size_t kTokenSize{32 * 2};                  // 32-bytes as hex chars
static constexpr size_t kPrefixedTokenSize{2 + kTokenSize};  // "0x" + 32-bytes as hex chars

std::string generate_jwt_token(const std::filesystem::path& file_path) {
    // Check input file path is not empty
    if (file_path.empty()) {
        const auto error_msg{"Empty JWT file path"};
        SILK_ERROR << error_msg;
        throw std::runtime_error{error_msg};
    }
    if (!std::filesystem::exists(file_path)) {
        std::filesystem::create_directories(file_path.parent_path());
    }

    std::string jwt_token;
    jwt_token.reserve(kTokenSize);

    // Generate a random 32-bytes hex token (not including prefix)
    RandomNumber rnd{0, 15};
    for (int i = 0; i < 64; ++i) {
        jwt_token += kHexCharacters[rnd.generate_one()];
    }
    SILK_INFO << "JWT token written to file: " << file_path.string();

    std::ofstream write_file{file_path};
    write_file << "0x" << jwt_token;

    return hex_to_string(jwt_token);
}

std::string load_jwt_token(const std::filesystem::path& file_path) {
    // Check input file path is not empty
    if (file_path.empty()) {
        const auto error_msg{"Empty JWT file path"};
        SILK_ERROR << error_msg;
        throw std::runtime_error{error_msg};
    }

    // If the input file does not exist, make a new JWT token since we don't have one
    if (!std::filesystem::exists(file_path)) {
        return generate_jwt_token(file_path);
    }

    // Check input file has expected size
    const auto file_size = std::filesystem::file_size(file_path);
    if (file_size != kPrefixedTokenSize && file_size != kTokenSize) {
        const auto error_msg{"Unexpected JWT file size: " + std::to_string(file_size)};
        SILK_ERROR << error_msg;
        throw std::runtime_error{error_msg};
    }

    std::string jwt_token;
    jwt_token.reserve(kPrefixedTokenSize);

    // Read JWT token from input file strictly checking content size
    std::ifstream read_file{file_path};
    read_file >> jwt_token;

    // Get rid of prefix if any
    if (jwt_token.starts_with("0x") || jwt_token.starts_with("0X")) {
        jwt_token = jwt_token.substr(2);
    }

    if (jwt_token.size() != kTokenSize) {
        const auto error_msg{"JWT token has wrong size: " + std::to_string(jwt_token.size())};
        SILK_ERROR << error_msg;
        throw std::runtime_error{error_msg};
    }
    read_file.close();

    SILK_INFO << "JWT secret read from file: " << file_path.string();

    return hex_to_string(jwt_token);
}

}  // namespace silkworm
