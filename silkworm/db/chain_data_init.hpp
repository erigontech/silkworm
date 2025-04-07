// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/chain/config.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/db/prune_mode.hpp>

namespace silkworm::db {

struct ChainDataInitSettings {
    datastore::kvdb::EnvConfig chaindata_env_config;
    db::PruneMode prune_mode;
    ChainId network_id{0};
    bool init_if_empty{true};
};

//! \brief Ensure database is ready to take off and consistent with command line arguments
ChainConfig chain_data_init(const ChainDataInitSettings& node_settings);

}  // namespace silkworm::db
