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

#include "db_checklist.hpp"

#include <regex>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::cmd::common {

void run_db_checklist(NodeSettings& node_settings, bool init_if_empty) {
    node_settings.data_directory->deploy();                                  // Ensures all subdirs are present
    bool chaindata_exclusive{node_settings.chaindata_env_config.exclusive};  // Save setting
    {
        auto& config = node_settings.chaindata_env_config;
        config.path = node_settings.data_directory->chaindata().path().string();
        config.create =
            !std::filesystem::exists(db::get_datafile_path(node_settings.data_directory->chaindata().path()));
        config.exclusive = true;  // Will be cleared after this phase
    }

    // Open chaindata environment and check tables are consistent
    log::Info("Opening database", {"path", node_settings.data_directory->chaindata().path().string()});
    auto chaindata_env{db::open_env(node_settings.chaindata_env_config)};
    db::RWTxnManaged tx(chaindata_env);

    // Ensures all tables are present
    db::table::check_or_create_chaindata_tables(tx);
    log::Info("Database schema", {"version", db::read_schema_version(tx)->to_string()});

    // Detect the highest downloaded header. We need that to detect if we can apply changes in chain config and/or
    // prune mode
    const auto header_download_progress{db::stages::read_stage_progress(tx, db::stages::kHeadersKey)};

    // Check db is initialized with chain config
    {
        node_settings.chain_config = db::read_chain_config(tx);
        if (!node_settings.chain_config.has_value() && init_if_empty) {
            auto source_data{read_genesis_data(node_settings.network_id)};
            auto genesis_json = nlohmann::json::parse(source_data, nullptr, /* allow_exceptions = */ false);
            if (genesis_json.is_discarded()) {
                throw std::runtime_error("Could not initialize db for chain id " +
                                         std::to_string(node_settings.network_id) + " : unknown network");
            }
            log::Message("Priming database", {"network id", std::to_string(node_settings.network_id)});
            db::initialize_genesis(tx, genesis_json, /*allow_exceptions=*/true);
            tx.commit_and_renew();
            node_settings.chain_config = db::read_chain_config(tx);
        }

        if (!node_settings.chain_config.has_value()) {
            throw std::runtime_error("Unable to retrieve chain configuration");
        }

        const ChainId chain_id{node_settings.chain_config->chain_id};
        if (chain_id != node_settings.network_id) {
            throw std::runtime_error("Incompatible network id. Command line expects " +
                                     std::to_string(node_settings.network_id) + "; Database has " +
                                     std::to_string(chain_id));
        }

        const auto known_chain{kKnownChainConfigs.find(chain_id)};
        if (known_chain && **known_chain != *(node_settings.chain_config)) {
            // If loaded config is known we must ensure is up-to-date with hardcoded one
            // Loop all respective JSON members to find discrepancies
            auto known_chain_config_json{(*known_chain)->to_json()};
            auto active_chain_config_json{node_settings.chain_config->to_json()};
            bool new_members_added{false};
            bool old_members_changed(false);
            for (auto& [known_key, known_value] : known_chain_config_json.items()) {
                if (!active_chain_config_json.contains(known_key)) {
                    // Is this new key a definition of a new fork block or a bomb delay block ?
                    // If so we need to check its new value must be **beyond** the highest
                    // header processed.

                    const std::regex block_pattern(R"(Block$)", std::regex_constants::icase);
                    if (std::regex_match(known_key, block_pattern)) {
                        // New forkBlock definition (as well as bomb defusing block) must be "activated" to be relevant.
                        // By "activated" we mean it has to have a value > 0. Code should also take into account
                        // different chain_id(s) if special features are embedded from genesis
                        // All our chain configurations inherit from ChainConfig which necessarily needs to be extended
                        // to allow derivative chains to support new fork blocks

                        if (const auto known_value_activation{known_value.get<uint64_t>()};
                            known_value_activation > 0 && known_value_activation <= header_download_progress) {
                            throw std::runtime_error("Can't apply new chain config key " + known_key + "with value " +
                                                     std::to_string(known_value_activation) +
                                                     " as the database has already blocks up to " +
                                                     std::to_string(header_download_progress));
                        }
                    }

                    new_members_added = true;
                    continue;
                }

                const auto active_value{active_chain_config_json[known_key]};
                if (active_value.type_name() != known_value.type_name()) {
                    throw std::runtime_error("Hard-coded chain config key " + known_key + " has type " +
                                             std::string(known_value.type_name()) +
                                             " whilst persisted config has type " +
                                             std::string(active_value.type_name()));
                }

                if (known_value.is_number()) {
                    // Check whether activation value has been modified
                    const auto known_value_activation{known_value.get<uint64_t>()};
                    const auto active_value_activation{active_value.get<uint64_t>()};
                    if (known_value_activation != active_value_activation) {
                        const bool must_throw{
                            // Can't de-activate an already activated fork block
                            (!known_value_activation && active_value_activation &&
                             active_value_activation <= header_download_progress) ||
                            // Can't activate a fork block BEFORE current height
                            (!active_value_activation && known_value_activation &&
                             known_value_activation <= header_download_progress) ||
                            // Can change activation height BEFORE current height
                            (known_value_activation && active_value_activation &&
                             std::min(known_value_activation, active_value_activation) <=
                                 header_download_progress)};
                        if (must_throw) {
                            throw std::runtime_error("Can't apply modified chain config key " +
                                                     known_key + " from " +
                                                     std::to_string(active_value_activation) + " to " +
                                                     std::to_string(known_value_activation) +
                                                     " as the database has already headers up to " +
                                                     std::to_string(header_download_progress));
                        }
                        old_members_changed = true;
                    }
                }
            }

            if (new_members_added || old_members_changed) {
                db::update_chain_config(tx, **known_chain);
                tx.commit_and_renew();
                node_settings.chain_config = **known_chain;
            }
        }

        // Load genesis_hash
        node_settings.chain_config->genesis_hash = db::read_canonical_header_hash(tx, 0);
        if (!node_settings.chain_config->genesis_hash.has_value())
            throw std::runtime_error("Could not load genesis hash");

        log::Info("Starting Silkworm", {"chain", (known_chain ? std::to_string(chain_id) : "unknown/custom"),
                                        "config", node_settings.chain_config->to_json().dump()});
    }

    // Detect prune-mode and verify is compatible
    {
        auto db_prune_mode{db::read_prune_mode(*tx)};
        if (db_prune_mode != node_settings.prune_mode) {
            // In case we have mismatching modes (cli != db) we prevent
            // further execution ONLY if we've already synced something
            if (header_download_progress) {
                throw std::runtime_error("Can't change prune_mode on already synced data. Expected " +
                                         db_prune_mode.to_string() + " got " + node_settings.prune_mode.to_string());
            }
            db::write_prune_mode(*tx, node_settings.prune_mode);
            node_settings.prune_mode = db::PruneMode(db::read_prune_mode(*tx));
        }
        log::Info("Effective pruning", {"mode", node_settings.prune_mode.to_string()});
    }

    tx.commit_and_stop();
    chaindata_env.close();
    node_settings.chaindata_env_config.exclusive = chaindata_exclusive;
    node_settings.chaindata_env_config.create = false;  // Has already been created
}

}  // namespace silkworm::cmd::common
