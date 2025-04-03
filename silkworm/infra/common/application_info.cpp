// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "application_info.hpp"

#include <silkworm/buildinfo.h>

namespace silkworm {

std::string get_node_name_from_build_info(const buildinfo* info) {
    std::string node_name = info->project_name;
    node_name.append("/");
    node_name.append(info->git_branch);
    node_name.append(info->project_version);
    node_name.append("/");
    node_name.append(info->system_name);
    node_name.append("-");
    node_name.append(info->system_processor);
    node_name.append("_");
    node_name.append(info->build_type);
    node_name.append("/");
    node_name.append(info->compiler_id);
    node_name.append("-");
    node_name.append(info->compiler_version);
    return node_name;
}

std::string make_client_id_from_build_info(const buildinfo& info) {
    return std::string(info.project_name) +
           "/v" + info.project_version +
           "/" + info.system_name + "-" + info.system_processor +
           "/" + info.compiler_id + "-" + info.compiler_version;
}

std::string build_info_to_string(const buildinfo* info) {
    std::string description{"version: "};
    description.append(info->git_branch);
    description.append(info->project_version);
    description.append(" build: ");
    description.append(info->system_name);
    description.append("-");
    description.append(info->system_processor);
    description.append("_");
    description.append(info->build_type);
    description.append(" compiler: ");
    description.append(info->compiler_id);
    description.append("-");
    description.append(info->compiler_version);
    return description;
}

ApplicationInfo make_application_info(const buildinfo* info) {
    return {
        .version = info->project_version,
        .commit_hash = info->git_commit_hash,
        .build_description = build_info_to_string(info),
        .node_name = get_node_name_from_build_info(info),
        .client_id = make_client_id_from_build_info(*info),
    };
}

log::Args build_info_as_log_args(const buildinfo* info) {
    return {
        "version",
        std::string(info->git_branch) + std::string(info->project_version),
        "build",
        std::string(info->system_name) + "-" + std::string(info->system_processor) + " " + std::string(info->build_type),
        "compiler",
        std::string(info->compiler_id) + " " + std::string(info->compiler_version),
    };
}

}  // namespace silkworm
