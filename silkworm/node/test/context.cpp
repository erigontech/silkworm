/*
   Copyright 2022 The Silkworm Authors

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

#include "context.hpp"

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/node/db/genesis.hpp>
#include <silkworm/node/db/tables.hpp>

namespace silkworm::test {

Context::Context(bool with_create_tables, bool in_memory) {
    node_settings_.data_directory = std::make_unique<DataDirectory>(tmp_dir_.path(), /*create=*/true);
    node_settings_.chain_config = kMainnetConfig;
    node_settings_.chain_config->genesis_hash.emplace(kMainnetGenesisHash);
    node_settings_.chaindata_env_config = {
        .path = node_settings_.data_directory->chaindata().path().string(),
        .create = true,
        .readonly = false,
        .exclusive = false,
        .in_memory = in_memory,
    };
    node_settings_.prune_mode = std::make_unique<db::PruneMode>();
    env_ = db::open_env(node_settings_.chaindata_env_config);
    txn_ = std::make_unique<db::RWTxnManaged>(env_);
    if (with_create_tables) {
        db::table::check_or_create_chaindata_tables(*txn_);
    }
}

void Context::add_genesis_data() {
    bool allow_exceptions = false;
    auto source_data = read_genesis_data(node_settings_.chain_config->chain_id);
    auto genesis_json = nlohmann::json::parse(source_data, nullptr, allow_exceptions);
    db::initialize_genesis(*txn_, genesis_json, allow_exceptions);
}

}  // namespace silkworm::test
