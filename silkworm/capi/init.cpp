// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "init.h"

#include <silkworm/buildinfo.h>
#include <silkworm/db/capi/component.hpp>
#include <silkworm/db/capi/db.h>
#include <silkworm/db/datastore/kvdb/mdbx_version.hpp>
#include <silkworm/infra/common/log.hpp>

#include "common/instance.hpp"
#include "common/parse_path.hpp"
#include "instance.hpp"
#include "make_log_settings.hpp"

using namespace silkworm;
using namespace silkworm::capi;

static bool is_initialized{false};

//! Generate log arguments for Silkworm library version
static log::Args log_args_for_version() {
    const auto build_info{silkworm_get_buildinfo()};
    return {
        "git_branch",
        std::string(build_info->git_branch),
        "git_tag",
        std::string(build_info->project_version),
        "git_commit",
        std::string(build_info->git_commit_hash)};
}

SILKWORM_EXPORT int silkworm_init(SilkwormHandle* handle, const struct SilkwormSettings* settings) SILKWORM_NOEXCEPT {
    using namespace datastore::kvdb;

    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!settings) {
        return SILKWORM_INVALID_SETTINGS;
    }
    if (std::strlen(settings->data_dir_path) == 0) {
        return SILKWORM_INVALID_PATH;
    }
    if (!is_compatible_mdbx_version(settings->libmdbx_version, silkworm_libmdbx_version(), MdbxVersionCheck::kExact)) {
        return SILKWORM_INCOMPATIBLE_LIBMDBX;
    }
    if (is_initialized) {
        return SILKWORM_TOO_MANY_INSTANCES;
    }

    is_initialized = true;

    log::Settings log_settings{make_log_settings(settings->log_verbosity)};
    log::init(log_settings);

    auto data_dir_path = parse_path(settings->data_dir_path);

    silkworm::capi::CommonComponent common{
        .log_settings = std::move(log_settings),
        .context_pool_settings = {
            .num_contexts = settings->num_contexts > 0 ? settings->num_contexts : silkworm::concurrency::kDefaultNumContexts,
        },
        .data_dir_path = data_dir_path,
    };

    auto snapshots_dir_path = DataDirectory{data_dir_path}.snapshots().path();
    auto blocks_repository = db::blocks::make_blocks_repository(
        snapshots_dir_path,
        /* open = */ false,
        settings->blocks_repo_index_salt);
    auto state_repository_latest = db::state::make_state_repository_latest(
        snapshots_dir_path,
        /* open = */ false,
        settings->state_repo_index_salt);
    auto state_repository_historical = db::state::make_state_repository_historical(
        snapshots_dir_path,
        /* open = */ false,
        settings->state_repo_index_salt);
    db::capi::Component db{
        .blocks_repository = std::move(blocks_repository),
        .state_repository_latest = std::move(state_repository_latest),
        .state_repository_historical = std::move(state_repository_historical),
        .chaindata = {},
        .query_caches = snapshots::QueryCaches{db::state::make_query_caches_schema(), snapshots_dir_path, settings->state_repo_index_salt},
    };

    // NOLINTNEXTLINE(bugprone-unhandled-exception-at-new)
    *handle = new ::SilkwormInstance{};
    (*handle)->common = std::move(common);
    (*handle)->db = std::make_unique<db::capi::Component>(std::move(db));

    log::Info{"Silkworm build info", log_args_for_version()};  // NOLINT(*-unused-raii)

    log::Debug{"[1/12] Silkworm initialized",  // NOLINT(*-unused-raii)
               {"data_dir", data_dir_path.string(),
                "snapshots_dir", snapshots_dir_path.string(),
                "blocks_repo_index_salt", std::to_string(settings->blocks_repo_index_salt),
                "state_repo_index_salt", std::to_string(settings->state_repo_index_salt)}};

    return SILKWORM_OK;
}

SILKWORM_EXPORT int silkworm_fini(SilkwormHandle handle) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    delete handle;

    is_initialized = false;

    return SILKWORM_OK;
}
