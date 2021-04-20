/*
   Copyright 2021 The Silkworm Authors

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

#include <stdlib.h>

#include <fstream>
#include <filesystem>
#include <iostream>

#include <CLI/CLI.hpp>
#include <boost/endian/conversion.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/common/chain_genesis.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/trie/hash_builder.hpp>
#include <silkworm/types/account.hpp>

using namespace silkworm;

constexpr uint8_t genesis_body[] = {195, 128, 128, 192};
constexpr uint8_t genesis_receipts[] = {246};
constexpr evmc::bytes32 kNullOmmers{0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347_bytes32};

std::string last_header_key = "LastHeader";

int main(int argc, char* argv[]) {
    namespace fs = std::filesystem;
    int chain_id{-1};
    CLI::App app{"Initializes database with genesis json file"};

    std::string out;
    std::string genesis;
    size_t map_size{
        1 *
        kMebi};  // As we're basically creating a new db set an initial map_size (Windows does not create it without)

    app.add_option("--out", out, "Path to new chaindata folder (must exist)", true)
        ->required()
        ->check(CLI::ExistingDirectory);

    auto genesis_opt =
        app.add_option("--genesis", genesis, "Path to the genesis json file", true)->check(CLI::ExistingFile);
    auto chain_id_opt = app.add_option("--chainid", chain_id, "Specify id of the chain to generate")
                            ->excludes(genesis_opt)
                            ->check(CLI::Range(0u, 65535u));

    CLI11_PARSE(app, argc, argv);

    // Either --chainId or --genesis are mandatory
    if (!genesis_opt->count() && !chain_id_opt->count()) {
        std::cerr << "\nError: Provide either a custom genesis file or a known chain_id" << std::endl;
        return -1;
    }

    // Check destination directory
    if (fs::exists(fs::path(out) / fs::path("data.mdb"))) {
        std::cerr << "\nError : A data file (data.mdb) already exists in target folder" << std::endl;
        return -1;
    }

    // Read data from selected source
    std::string source_data;

    // If provided a json file parse it
    if (genesis_opt->count()) {
        std::ifstream t(genesis.data());
        source_data = std::string((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
    } else {
        // Parse from a known set of configs
        switch (chain_id) {
            case 1:
                source_data.assign(genesis_mainnet_data(), sizeof_genesis_mainnet_data());
                break;
            case 4:
                source_data.assign(genesis_rinkeby_data(), sizeof_genesis_rinkeby_data());
                break;
            case 5:
                source_data.assign(genesis_goerli_data(), sizeof_genesis_goerli_data());
                break;
            default:
                SILKWORM_LOG(LogLevel::Error) << "Unknown chain id: " << chain_id << std::endl;
                return -1;
        }
    }

    // Parse Json data
    auto genesis_json{nlohmann::json::parse(source_data, nullptr, /* allow_exceptions = */ false)};
    if (genesis_json == nlohmann::json::value_t::discarded) {
        std::cerr << "\nError : Provided data is not a valid JSON format" << std::endl;
        return -1;
    }

    // Sanity checks over collected data
    if (!genesis_json.contains("difficulty") || !genesis_json.contains("nonce") || !genesis_json.contains("gasLimit") ||
        !genesis_json.contains("timestamp") || !genesis_json.contains("extraData") ||
        !genesis_json.contains("config") || !genesis_json["config"].contains("chainId") ||
        !genesis_json["config"]["chainId"].is_number()) {
        SILKWORM_LOG(LogLevel::Error) << "Incomplete Genesis File" << std::endl;
        return -1;
    }

    bool res{false};
    try {
        // Prime directories and DB
        lmdb::DatabaseConfig db_config{out};
        db_config.set_readonly(false);
        db_config.map_size = map_size;
        std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_config)};
        std::unique_ptr<lmdb::Transaction> txn{env->begin_rw_transaction()};
        db::table::create_all(*txn);

        auto block_number{Bytes(8, '\0')};
        evmc::bytes32 root_hash;

        if (genesis_json.contains("alloc")) {
            if (!genesis_json["alloc"].is_object()) {
                throw std::invalid_argument("alloc member is not object");
            }

            // Filling account + constructing genesis root hash
            std::map<evmc::bytes32, Bytes> account_rlp;
            // Tables used
            auto plainstate_table{txn->open(db::table::kPlainState)};
            auto account_changeset_table{txn->open(db::table::kPlainAccountChangeSet)};

            // Iterate over allocs
            for (auto& item : genesis_json["alloc"].items()) {
                if (!item.value().is_object() || !item.value().contains("balance") ||
                    !item.value()["balance"].is_string()) {
                    throw std::invalid_argument("alloc address " + item.key() + " has badly formatted allocation");
                }

                auto address_bytes{from_hex(item.key())};
                if (address_bytes == std::nullopt || address_bytes.value().length() != kAddressLength) {
                    throw std::invalid_argument("alloc address " + item.key() +
                                                " is not valid. Either not hex or not " +
                                                std::to_string(kAddressLength) + " bytes");
                }

                auto balance_str{item.value()["balance"].get<std::string>()};
                Account account{0, intx::from_string<intx::uint256>(balance_str)};

                // Make the account
                account_changeset_table->put(block_number, *address_bytes);
                plainstate_table->put(*address_bytes, account.encode_for_storage(true));

                // Fills hash builder
                auto hash{keccak256(*address_bytes)};
                account_rlp[to_bytes32(hash.bytes)] = account.rlp(kEmptyRoot);
            }

            auto it{account_rlp.cbegin()};
            trie::HashBuilder hb{full_view(it->first), it->second};
            for (++it; it != account_rlp.cend(); ++it) {
                hb.add(full_view(it->first), it->second);
            }
            root_hash = hb.root_hash();

        } else {
            root_hash = kEmptyRoot;
        }

        // Fill Header
        BlockHeader header;
        header.ommers_hash = kNullOmmers;
        header.state_root = root_hash;
        header.transactions_root = kEmptyRoot;
        header.receipts_root = kEmptyRoot;

        auto difficulty_str{genesis_json["difficulty"].get<std::string>()};
        header.difficulty = intx::from_string<intx::uint256>(difficulty_str);

        header.gas_limit = std::stoull(genesis_json["gasLimit"].get<std::string>().c_str(), nullptr, 0);
        header.timestamp = std::stoull(genesis_json["timestamp"].get<std::string>().c_str(), nullptr, 0);

        auto nonce_str{genesis_json["nonce"].get<std::string>()};
        auto nonce_bytes{from_hex(nonce_str)};
        auto diff_nonce_size(8 - nonce_bytes->size());
        for (size_t i = 0; i < nonce_bytes->size(); i++)
            header.nonce[i + diff_nonce_size] = nonce_bytes->at(i + diff_nonce_size);

        // Write header
        auto blockhash{header.hash()};

        Bytes rlp_header;
        rlp::encode(rlp_header, header);
        Bytes key(8 + kHashLength, '\0');
        std::memcpy(&key[8], blockhash.bytes, kHashLength);
        txn->open(db::table::kHeaders)->put(key, rlp_header);
        txn->open(db::table::kCanonicalHashes)->put(block_number, full_view(blockhash.bytes));
        // Write body
        txn->open(db::table::kBlockBodies)->put(key, Bytes(genesis_body, 4));
        txn->open(db::table::kDifficulty)->put(key, intx::as_bytes(header.difficulty));
        txn->open(db::table::kBlockReceipts)->put(key.substr(0, 8), Bytes(genesis_receipts, 1));
        txn->open(db::table::kHeadHeader)
            ->put(Bytes(reinterpret_cast<const uint8_t*>(last_header_key.c_str()), last_header_key.size()),
                  full_view(blockhash.bytes));
        txn->open(db::table::kHeaderNumbers)->put(full_view(blockhash.bytes), key.substr(0, 8));
        // Write Chain Config
        auto chain_config{genesis_json["config"].dump()};
        txn->open(db::table::kConfig)
            ->put(full_view(blockhash.bytes),
                  Bytes(reinterpret_cast<const uint8_t*>(chain_config.c_str()), chain_config.size()));

        lmdb::err_handler(txn->commit());
        txn.reset();
        res = true;
    } catch (const std::exception& ex) {
        std::cerr << "\nUnexpected error : " << ex.what() << std::endl;
    }

    if (!res) {
        // Delete created db (if any)
        fs::path out_path(out);
        fs::path out_file_path(out / fs::path("data.mdb"));
        fs::path out_lock_path(out / fs::path("lock.mdb"));
        if (fs::exists(out_file_path)) {
            fs::remove(out_file_path);
        }
        if (fs::exists(out_lock_path)) {
            fs::remove(out_lock_path);
        }
    } else {
        std::cout << "\nDatabase initialized" << std::endl;
    }

    return res ? 0 : -1;
}
