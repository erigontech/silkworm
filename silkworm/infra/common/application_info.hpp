// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <silkworm/infra/common/log.hpp>

struct buildinfo;

namespace silkworm {

//! Application versioning information
struct ApplicationInfo {
    std::string version;            // Extracted from version control system
    std::string commit_hash;        // Extracted from version control system
    std::string build_description;  // Containing compiler and platform
    std::string node_name;          // Complete node name with identifier and build info
    std::string client_id;          // P2P RLPx clientId
};

//! Assemble the complete node name using the Cable build information
std::string get_node_name_from_build_info(const buildinfo* info);

//! P2P RLPx clientId from the Cable build information
std::string make_client_id_from_build_info(const buildinfo& info);

//! Assemble the build description using the Cable build information
std::string get_description_from_build_info(const buildinfo* info);

//! Create the application versioning information from the Cable build information
ApplicationInfo make_application_info(const buildinfo* info);

//! Format the Cable build information as log arguments
log::Args build_info_as_log_args(const buildinfo* info);

}  // namespace silkworm
