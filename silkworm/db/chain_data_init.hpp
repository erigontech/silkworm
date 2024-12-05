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
