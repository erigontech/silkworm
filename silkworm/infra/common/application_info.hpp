/*
   Copyright 2024 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

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
std::string build_info_to_string(const buildinfo* info);

//! Create the application versioning information from the Cable build information
ApplicationInfo make_application_info(const buildinfo* info);

//! Format the Cable build information as log arguments
log::Args build_info_as_log_args(const buildinfo* info);

}  // namespace silkworm
