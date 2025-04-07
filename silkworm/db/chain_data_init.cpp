// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "chain_data_init.hpp"

#include <regex>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::db {

ChainConfig chain_data_init(const ChainDataInitSettings& node_settings) {
    // Output mdbx build info
    log::Debug(
        "libmdbx",
        {
            "version",
            mdbx::get_version().git.describe,
            "build",
            mdbx::get_build().target,
            "compiler",
            mdbx::get_build().compiler,
        });

    auto chaindata_env_config = node_settings.chaindata_env_config;
    chaindata_env_config.create = !std::filesystem::exists(datastore::kvdb::get_datafile_path(chaindata_env_config.path));
    chaindata_env_config.exclusive = true;

    // Open chaindata environment and check tables are consistent
    log::Info("Opening database", {"path", chaindata_env_config.path});
    mdbx::env_managed chaindata_env = open_env(chaindata_env_config);
    datastore::kvdb::RWTxnManaged tx(chaindata_env);

    // Ensures all tables are present
    table::check_or_create_chaindata_tables(tx);
    log::Info("Database schema", {"version", read_schema_version(tx)->to_string()});

    // Detect the max downloaded header. We need that to detect if we can apply changes in chain config and/or
    // prune mode
    const auto header_download_progress{stages::read_stage_progress(tx, stages::kHeadersKey)};

    // Check db is initialized with chain config
    std::optional<ChainConfig> chain_config;
    {
        chain_config = read_chain_config(tx);
        if (!chain_config.has_value() && node_settings.init_if_empty) {
            auto source_data{read_genesis_data(node_settings.network_id)};
            auto genesis_json = nlohmann::json::parse(source_data, nullptr, /* allow_exceptions = */ false);
            if (genesis_json.is_discarded()) {
                throw std::runtime_error("Could not initialize db for chain id " +
                                         std::to_string(node_settings.network_id) + " : unknown network");
            }
            log::Debug("Priming database", {"network id", std::to_string(node_settings.network_id)});
            initialize_genesis(tx, genesis_json, /*allow_exceptions=*/true);
            tx.commit_and_renew();
            chain_config = read_chain_config(tx);
        }

        if (!chain_config.has_value()) {
            throw std::runtime_error("Unable to retrieve chain configuration");
        }

        const ChainId chain_id = chain_config->chain_id;
        if (chain_id != node_settings.network_id) {
            throw std::runtime_error("Incompatible network id. Command line expects " +
                                     std::to_string(node_settings.network_id) + "; Database has " +
                                     std::to_string(chain_id));
        }

        const auto known_chain{kKnownChainConfigs.find(chain_id)};
        if (known_chain && **known_chain != *chain_config) {
            // If loaded config is known we must ensure is up-to-date with hardcoded one
            // Loop all respective JSON members to find discrepancies
            auto known_chain_config_json{(*known_chain)->to_json()};
            auto active_chain_config_json = chain_config->to_json();
            bool new_members_added{false};
            bool old_members_changed(false);
            for (auto& [known_key, known_value] : known_chain_config_json.items()) {
                if (!active_chain_config_json.contains(known_key)) {
                    // Is this new key a definition of a new fork block or a bomb delay block ?
                    // If so we need to check its new value must be **beyond** the max
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
                            // Can't activate a fork block BEFORE current block_num
                            (!active_value_activation && known_value_activation &&
                             known_value_activation <= header_download_progress) ||
                            // Can change activation block_num BEFORE current block_num
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
                update_chain_config(tx, **known_chain);
                tx.commit_and_renew();
                chain_config = **known_chain;
            }
        }

        // Load genesis_hash
        chain_config->genesis_hash = read_canonical_header_hash(tx, 0);
        if (!chain_config->genesis_hash.has_value())
            throw std::runtime_error("Could not load genesis hash");

        log::Info("Starting Silkworm", {"chain", (known_chain ? std::to_string(chain_id) : "unknown/custom"),
                                        "config", chain_config->to_json().dump()});
    }

    // Detect prune-mode and verify is compatible
    {
        auto db_prune_mode{read_prune_mode(*tx)};
        if (db_prune_mode != node_settings.prune_mode) {
            // In case we have mismatching modes (cli != db) we prevent
            // further execution ONLY if we've already synced something
            if (header_download_progress) {
                throw std::runtime_error("Can't change prune_mode on already synced data. Expected " +
                                         db_prune_mode.to_string() + " got " + node_settings.prune_mode.to_string());
            }
            write_prune_mode(*tx, node_settings.prune_mode);
        }
        log::Info("Effective pruning", {"mode", node_settings.prune_mode.to_string()});
    }

    tx.commit_and_stop();
    chaindata_env.close();

    return std::move(*chain_config);
}

}  // namespace silkworm::db
