// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/node/common/node_settings.hpp>

namespace silkworm::node::test_util {

inline NodeSettings make_node_settings_from_temp_chain_data(const db::test_util::TempChainData& db) {
    return NodeSettings{
        .data_directory = std::make_unique<DataDirectory>(db.dir().path(), false),
        .chaindata_env_config = db.chaindata_env_config(),
        .chain_config = db.chain_config(),
        .prune_mode = db.prune_mode(),
    };
}

}  // namespace silkworm::node::test_util
