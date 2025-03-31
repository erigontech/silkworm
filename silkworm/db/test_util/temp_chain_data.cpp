// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "temp_chain_data.hpp"

#include <nlohmann/json.hpp>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/db/tables.hpp>

namespace silkworm::db::test_util {

using namespace silkworm::datastore::kvdb;

TempChainData::TempChainData(bool with_create_tables, bool in_memory)
    : data_dir_(tmp_dir_.path(), /*create=*/true),
      chain_config_(kMainnetConfig),
      chaindata_env_config_(EnvConfig{
          .path = data_dir_.chaindata().path().string(),
          .create = true,
          .readonly = false,
          .exclusive = false,
          .in_memory = in_memory,
      }) {
    chain_config_.genesis_hash.emplace(kMainnetGenesisHash);

    env_ = std::make_unique<mdbx::env_managed>(open_env(chaindata_env_config_));
    txn_ = std::make_unique<RWTxnManaged>(chaindata_rw().start_rw_tx());

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
