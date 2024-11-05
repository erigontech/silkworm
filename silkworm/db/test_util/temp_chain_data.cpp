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

#include "temp_chain_data.hpp"

#include <nlohmann/json.hpp>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/db/tables.hpp>

namespace silkworm::db::test_util {

TempChainData::TempChainData(bool with_create_tables, bool in_memory)
    : data_dir_(tmp_dir_.path(), /*create=*/true),
      chain_config_(kMainnetConfig),
      chaindata_env_config_(db::EnvConfig{
          .path = data_dir_.chaindata().path().string(),
          .create = true,
          .readonly = false,
          .exclusive = false,
          .in_memory = in_memory,
      }) {
    chain_config_.genesis_hash.emplace(kMainnetGenesisHash);

    env_ = std::make_unique<mdbx::env_managed>(db::open_env(chaindata_env_config_));
    txn_ = std::make_unique<db::RWTxnManaged>(chaindata_rw().start_rw_tx());

    if (with_create_tables) {
        db::table::check_or_create_chaindata_tables(*txn_);
    }
}

void TempChainData::add_genesis_data() const {
    bool allow_exceptions = false;
    auto source_data = read_genesis_data(chain_config().chain_id);
    auto genesis_json = nlohmann::json::parse(source_data, nullptr, allow_exceptions);
    db::initialize_genesis(*txn_, genesis_json, allow_exceptions);
}

}  // namespace silkworm::db::test_util
