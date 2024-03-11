/*
   Copyright 2023 The Silkworm Authors

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

#include <silkworm/infra/common/directories.hpp>
#include <silkworm/node/common/node_settings.hpp>
#include <silkworm/node/db/test_util/temp_chain_data.hpp>

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
